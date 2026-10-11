"""Bounded background tasks with truthful cancellation and retained handles."""

import asyncio
import inspect
import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    CANCEL_REQUESTED = "cancel_requested"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL = {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}


@dataclass
class McpTask:
    id: str
    name: str
    status: TaskStatus = TaskStatus.PENDING
    owner: str = "default"
    progress: float = 0.0
    result: Optional[Any] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return {"id": self.id, "name": self.name, "status": self.status.value,
                "progress": self.progress, "result": self.result, "error": self.error,
                "created_at": self.created_at.isoformat(),
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "completed_at": self.completed_at.isoformat() if self.completed_at else None,
                "metadata": dict(self.metadata), "still_running": self.status not in TERMINAL}


class TaskManager:
    def __init__(self, max_tasks=100, cleanup_completed_after=300):
        self._tasks = {}
        self._running_futures = {}
        self._cancel_callbacks = {}
        self._async_tasks = set()
        self._lock = threading.RLock()
        self._max_tasks = max_tasks
        self._cleanup_after = cleanup_completed_after
        self._closed = False

    def _cleanup_old_tasks(self):
        now = datetime.now()
        for task_id, task in list(self._tasks.items()):
            if task.completed_at and (now - task.completed_at).total_seconds() > self._cleanup_after:
                self._tasks.pop(task_id)
        if len(self._tasks) >= self._max_tasks:
            for task_id, task in list(self._tasks.items()):
                if task.status in TERMINAL:
                    self._tasks.pop(task_id)
                    if len(self._tasks) < self._max_tasks:
                        break

    async def submit(self, func, name="task", *args, owner="default", cancel_callback=None,
                     metadata=None, **kwargs):
        with self._lock:
            self._cleanup_old_tasks()
            if self._closed:
                raise RuntimeError("Task manager is closed")
            if len(self._tasks) >= self._max_tasks:
                raise RuntimeError("Task capacity reached; wait for active tasks")
            task_id = uuid.uuid4().hex
            self._tasks[task_id] = McpTask(task_id, name, owner=owner, metadata=metadata or {})
            if cancel_callback is not None:
                self._cancel_callbacks[task_id] = cancel_callback
            if inspect.iscoroutinefunction(func):
                self._async_tasks.add(task_id)
            future = asyncio.create_task(self._run_task(task_id, func, args, kwargs))
            self._running_futures[task_id] = future
            future.add_done_callback(lambda done: self._finished_future(task_id, done))
        return task_id

    def _finished_future(self, task_id, future):
        with self._lock:
            self._running_futures.pop(task_id, None)
            self._cancel_callbacks.pop(task_id, None)
            self._async_tasks.discard(task_id)
            task = self._tasks.get(task_id)
            if task is not None and future.cancelled() and task.status not in TERMINAL:
                task.status = TaskStatus.CANCELLED
                task.completed_at = datetime.now()

    async def _run_task(self, task_id, func, args, kwargs):
        with self._lock:
            task = self._tasks[task_id]
            if task.status == TaskStatus.CANCELLED:
                return
            if task.status == TaskStatus.CANCEL_REQUESTED and task_id not in self._cancel_callbacks:
                task.status = TaskStatus.CANCELLED
                task.completed_at = datetime.now()
                return
            if task.status != TaskStatus.CANCEL_REQUESTED:
                task.status = TaskStatus.RUNNING
            task.started_at = datetime.now()
        try:
            if inspect.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = await asyncio.to_thread(func, *args, **kwargs)
            # Retain only bounded JSON, never live native objects.
            encoded = json.dumps(result, ensure_ascii=False, allow_nan=False)
            if len(encoded.encode("utf-8")) > 262_144:
                result = {"truncated": True, "message": "Task result exceeds 256 KiB; use bounded batches"}
            else:
                result = json.loads(encoded)
            with self._lock:
                task.result = result
                failed = isinstance(result, dict) and result.get("success") is False
                execution_status = (result.get("status") if isinstance(result, dict)
                                    and result.get("execution_id") and result.get("still_running") is False
                                    else None)
                execution_terminal = {"ok": TaskStatus.COMPLETED, "cancelled": TaskStatus.CANCELLED,
                                      "timeout": TaskStatus.FAILED, "input_required": TaskStatus.FAILED,
                                      "error": TaskStatus.FAILED}
                task.status = execution_terminal.get(
                    execution_status,
                    TaskStatus.CANCELLED if task.status == TaskStatus.CANCEL_REQUESTED
                    else TaskStatus.FAILED if failed else TaskStatus.COMPLETED,
                )
                if task.status == TaskStatus.COMPLETED:
                    task.progress = 1.0
                task.completed_at = datetime.now()
        except asyncio.CancelledError:
            with self._lock:
                task.status = TaskStatus.CANCELLED
                task.completed_at = datetime.now()
            raise
        except BaseException as exc:
            with self._lock:
                task.status = TaskStatus.FAILED
                task.error = f"{type(exc).__name__}: {exc}"[:4096]
                task.completed_at = datetime.now()

    def get_task(self, task_id, owner=None):
        with self._lock:
            task = self._tasks.get(task_id)
            return task if task is not None and (owner is None or task.owner == owner) else None

    def get_task_status(self, task_id, owner=None):
        with self._lock:
            task = self.get_task(task_id, owner)
            return task.to_dict() if task else {"id": task_id, "status": "unknown", "error": "Task not found"}

    def update_progress(self, task_id, progress, metadata=None):
        with self._lock:
            task = self._tasks.get(task_id)
            if task is not None and task.status not in TERMINAL:
                task.progress = max(0.0, min(1.0, progress))
                if metadata:
                    task.metadata.update(metadata)

    def cancel_task(self, task_id, owner=None):
        with self._lock:
            task = self.get_task(task_id, owner)
            if task is None or task.status in TERMINAL:
                return False
            task.status = TaskStatus.CANCEL_REQUESTED
            callback = self._cancel_callbacks.get(task_id)
            future = self._running_futures.get(task_id)
            # Pure coroutine tasks can be cancelled. Running sync functions and
            # native Python jobs must acknowledge completion themselves.
            cancel_future = callback is None and task_id in self._async_tasks
        if callback is not None:
            callback()
        elif cancel_future and future is not None:
            future.get_loop().call_soon_threadsafe(future.cancel)
        return True

    def list_tasks(self, status_filter=None, owner=None):
        with self._lock:
            return [task.to_dict() for task in self._tasks.values()
                    if (status_filter is None or task.status == status_filter)
                    and (owner is None or task.owner == owner)]

    def clear_completed(self):
        with self._lock:
            for task_id, task in list(self._tasks.items()):
                if task.status in TERMINAL:
                    self._tasks.pop(task_id)

    async def close(self):
        with self._lock:
            self._closed = True
            ids = list(self._running_futures)
        for task_id in ids:
            self.cancel_task(task_id)
        futures = list(self._running_futures.values())
        if futures:
            await asyncio.wait(futures, timeout=1)

    def __len__(self):
        with self._lock:
            return len(self._tasks)


_task_manager = None


def get_task_manager():
    global _task_manager
    if _task_manager is None:
        _task_manager = TaskManager()
    return _task_manager


def reset_task_manager():
    global _task_manager
    _task_manager = None
