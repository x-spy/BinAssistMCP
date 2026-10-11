"""Bounded output and lifecycle records for Python executions.

These records never retain BinaryViews, exception objects or traceback frames.
Cancellation is cooperative: a requested cancellation is not a completed job.
"""

from __future__ import annotations

import io
import copy
import json
import math
import threading
import time
import traceback
import uuid
from typing import Any, Dict


DEFAULT_OUTPUT_BYTES = 65_536
DEFAULT_PAGE_BYTES = 16_384
MAX_OUTPUT_BYTES = 1_000_000
MAX_ERROR_BYTES = 16_384
MAX_RESULT_BYTES = 65_536
MAX_RESULTS = 256


class ExecutionCancelled(BaseException):
    """Stop a script without being swallowed by ``except Exception``."""


class InputRequired(BaseException):
    """Interactive input cannot be supplied to an unattended script."""


def bounded_text(value: str, limit: int) -> str:
    """Bound UTF-8 bytes without splitting a code point."""
    return value[:limit].encode("utf-8", errors="replace")[:limit].decode("utf-8", errors="ignore")


class ConsoleOutputBuffer:
    """Coalesce small writes; reserve a separate bounded diagnostic budget."""

    def __init__(self, max_bytes: int = DEFAULT_OUTPUT_BYTES):
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
            raise ValueError("max_output_bytes must be an integer")
        if not 1024 <= max_bytes <= MAX_OUTPUT_BYTES:
            raise ValueError(f"max_output_bytes must be between 1024 and {MAX_OUTPUT_BYTES}")
        self.max_bytes = max_bytes
        self._lock = threading.RLock()
        self._events = []
        self._bytes = 0
        self._error_bytes = 0
        self._dropped_chars = 0
        self._dropped_bytes = 0
        self._sealed = False

    def seal(self):
        with self._lock:
            self._sealed = True

    def append(self, stream: str, text: Any) -> None:
        decoded = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else str(text)
        if not decoded:
            return
        if stream not in ("stdout", "stderr", "warning"):
            raise ValueError("Unknown output stream")
        with self._lock:
            if self._sealed:
                return
            used = self._error_bytes if stream == "stderr" else self._bytes
            cap = MAX_ERROR_BYTES if stream == "stderr" else self.max_bytes
            captured = bounded_text(decoded, max(0, cap - used))
            size = len(captured.encode("utf-8"))
            if len(self._events) >= 1024:
                captured, size = "", 0
            if captured:
                if not self._events or self._events[-1][0] != stream or self._events[-1][2] >= 4096:
                    self._events.append([stream, io.StringIO(), 0])
                self._events[-1][1].write(captured)
                self._events[-1][2] += size
                if stream == "stderr":
                    self._error_bytes += size
                else:
                    self._bytes += size
            self._dropped_chars += len(decoded) - len(captured)
            self._dropped_bytes += len(decoded.encode("utf-8", errors="replace")) - size

    def snapshot(self, offset: int = 0, limit: int = DEFAULT_OUTPUT_BYTES,
                 include_streams: bool = True) -> Dict[str, Any]:
        if not isinstance(offset, int) or offset < 0:
            raise ValueError("output_offset must be a nonnegative character offset")
        if not isinstance(limit, int) or not 4 <= limit <= MAX_OUTPUT_BYTES:
            raise ValueError(f"output_limit must be between 4 and {MAX_OUTPUT_BYTES}")
        with self._lock:
            events = [(stream, text.getvalue()) for stream, text, _ in self._events]
            combined = "".join(text for _, text in events)
            output = bounded_text(combined[offset:], limit)
            end = min(len(combined), offset + len(output))
            result = {
                "output": output,
                "output_offset": offset,
                "next_offset": end,
                "output_complete": end >= len(combined),
                "truncated": self._dropped_chars > 0,
                "dropped_chars": self._dropped_chars,
                "dropped_bytes": self._dropped_bytes,
                "retained_bytes": self._bytes + self._error_bytes,
            }
            if include_streams:
                # Stream fields describe the same page, never a second full copy.
                position = 0
                streams = {"stdout": [], "stderr": [], "warning": []}
                for stream, text in events:
                    left, right = max(0, offset - position), min(len(text), end - position)
                    if right > left:
                        streams[stream].append(text[left:right])
                    position += len(text)
                result.update({name: "".join(parts) for name, parts in streams.items()})
            return result


class Execution:
    """Thread-safe, bounded state for one accepted script."""

    def __init__(self, timeout: float, max_output_bytes: int, created=None):
        self.id = uuid.uuid4().hex
        self.created = time.monotonic() if created is None else created
        self.deadline = self.created + timeout
        self.timeout = timeout
        self.started = None
        self.finished = None
        self.done = threading.Event()
        self.cancel_event = threading.Event()
        self.lock = threading.RLock()
        self.output = ConsoleOutputBuffer(max_output_bytes)
        self.status = "pending"
        self.cancel_reason = None
        self.error = None
        self.context = {"address": None, "function": None}
        self.analysis = {}
        self.analysis_at_start = {}
        self.progress = 0.0
        self.message = ""
        self.results = []
        self.result_bytes = 0
        self.script_status = None
        self.payload_running = False
        self.active_children = 0
        self.bridge_error = False
        self.native_ready = threading.Event()
        self.input_ready = threading.Event()

    def request_cancel(self, reason: str = "cancelled") -> bool:
        with self.lock:
            if self.done.is_set():
                return False
            if self.cancel_reason is None:
                self.cancel_reason = reason
            self.cancel_event.set()
            self.status = "cancel_requested"
            return True

    def checkpoint(self, progress=None, message=None) -> None:
        with self.lock:
            if self.done.is_set():
                raise RuntimeError("Execution has finished; results and progress are immutable")
        if time.monotonic() >= self.deadline:
            self.request_cancel("timeout")
        if self.cancel_event.is_set():
            if self.cancel_reason == "input_required":
                raise InputRequired("Interactive input is unavailable; supply values in the script")
            raise ExecutionCancelled(self.cancel_reason or "cancelled")
        if progress is not None:
            value = float(progress)
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError("progress must be finite and between 0 and 1")
            with self.lock:
                if self.done.is_set():
                    raise RuntimeError("Execution has finished")
                self.progress = value
        if message is not None:
            with self.lock:
                if self.done.is_set():
                    raise RuntimeError("Execution has finished")
                self.message = bounded_text(str(message), 1024)

    def write(self, text, stream="stdout"):
        with self.lock:
            self.checkpoint()
            self.output.append(stream, text)

    def emit(self, value: Any) -> None:
        self.checkpoint()
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
        size = len(encoded.encode("utf-8"))
        with self.lock:
            self.checkpoint()
            if len(self.results) >= MAX_RESULTS or self.result_bytes + size > MAX_RESULT_BYTES:
                raise ValueError("Structured result budget exceeded; process a smaller batch")
            # Copy JSON data so later script mutation cannot alter a published result.
            self.results.append(json.loads(encoded))
            self.result_bytes += size

    def capture_error(self, exc: BaseException) -> None:
        description = traceback.TracebackException.from_exception(exc, capture_locals=False)
        text = "".join(description.format())
        with self.lock:
            if self.done.is_set():
                return
            self.error = {
                "type": type(exc).__name__,
                "message": bounded_text(str(exc), 2048),
                "traceback": bounded_text(text, MAX_ERROR_BYTES),
            }
            self.output.append("stderr", self.error["traceback"])

    def finish(self, status: str) -> None:
        with self.lock:
            if self.done.is_set():
                return
            if self.cancel_reason is not None:
                status = ("error" if self.cancel_reason == "child_error" else
                          self.cancel_reason if self.cancel_reason in ("timeout", "input_required") else "cancelled")
            self.status = status
            self.finished = time.monotonic()
            if status == "ok":
                self.progress = 1.0
            self.output.seal()
            self.done.set()

    def snapshot(self, output_offset=0, output_limit=DEFAULT_PAGE_BYTES,
                 include_streams=True, result_offset=0, result_limit=100) -> Dict[str, Any]:
        if not isinstance(result_offset, int) or result_offset < 0:
            raise ValueError("result_offset must be nonnegative")
        if not isinstance(result_limit, int) or not 1 <= result_limit <= MAX_RESULTS:
            raise ValueError(f"result_limit must be between 1 and {MAX_RESULTS}")
        with self.lock:
            end = self.finished or time.monotonic()
            started = self.started or end
            result = {
                "execution_id": self.id,
                "success": self.status == "ok" and self.done.is_set(),
                "status": self.status,
                "still_running": not self.done.is_set(),
                "active_children": self.active_children,
                "cancel_requested": self.cancel_event.is_set(),
                "cancel_reason": self.cancel_reason,
                "timed_out": self.cancel_reason == "timeout",
                "duration_ms": round((end - self.created) * 1000),
                "queue_ms": round((started - self.created) * 1000),
                "execution_ms": round((end - started) * 1000),
                "progress": self.progress,
                "message": self.message,
                "error": dict(self.error) if self.error else None,
                **self.context,
                "analysis": dict(self.analysis),
                "analysis_at_start": dict(self.analysis_at_start),
                "results": copy.deepcopy(self.results[result_offset:result_offset + result_limit]),
                "next_result_offset": min(len(self.results), result_offset + result_limit),
                "result_count": len(self.results),
            }
        result.update(self.output.snapshot(output_offset, output_limit, include_streams))
        return result
