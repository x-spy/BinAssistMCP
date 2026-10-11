"""Cooperative user-code tracing and structured Python thread lifetimes.

Hooks are installed only on the interpreter and its enrolled child threads.
The process-wide threading implementation is never monkey-patched. Native work
and standard-library bookkeeping finish normally before cancellation unwinds
user code. This is execution management for trusted scripts, not a sandbox.
"""

from contextlib import contextmanager
from concurrent.futures import Executor, ThreadPoolExecutor
import builtins
import sys
import threading
import time

from .execution import ExecutionCancelled, InputRequired


_THREAD_START = threading.Thread.start.__code__
_POOL_SUBMIT = ThreadPoolExecutor.submit.__code__
_EXECUTOR_ENTER = Executor.__enter__.__code__
_STDLIB = getattr(sys, "stdlib_module_names", frozenset())
_INTERNAL_PACKAGE = __package__
MAX_CHILD_THREADS = 64


class ExecutionScope:
    def __init__(self, execution):
        self.execution = execution
        self._lock = threading.RLock()
        self._children = {}
        self._managed_pools = set()
        self._owner_thread = threading.get_ident()
        self._started_threads = 0

    @staticmethod
    def _user_frame(frame):
        filename = frame.f_code.co_filename
        if filename.startswith("<binassist:"):
            return True
        qualified_module = frame.f_globals.get("__name__", "")
        module = qualified_module.split(".")[0]
        internal = (qualified_module == _INTERNAL_PACKAGE
                    or qualified_module.startswith(_INTERNAL_PACKAGE + "."))
        return (module not in _STDLIB and module != "binaryninja" and not internal
                and not filename.startswith("<frozen ")
                and frame.f_code.co_name != "__del__")

    @contextmanager
    def tracing(self):
        previous_trace, previous_profile = sys.gettrace(), sys.getprofile()
        interrupting = False

        def checkpoint():
            nonlocal interrupting
            if not interrupting:
                try:
                    self.execution.checkpoint()
                except (ExecutionCancelled, InputRequired):
                    # One unwind per thread leaves finally/with cleanup usable.
                    interrupting = True
                    raise

        def trace(frame, event, arg):
            nonlocal interrupting
            if event == "exception" and isinstance(arg[1], (ExecutionCancelled, InputRequired)):
                interrupting = True
            if self._user_frame(frame):
                checkpoint()
                return trace
            return None

        def profile(frame, event, arg):
            if event == "return" and frame.f_code is _EXECUTOR_ENTER and isinstance(arg, ThreadPoolExecutor):
                with self._lock:
                    self._managed_pools.add(arg)
            if event == "call" and frame.f_code is _POOL_SUBMIT:
                pool = frame.f_locals["self"]
                with self._lock:
                    if pool not in self._managed_pools or any(t not in self._children for t in pool._threads):
                        raise RuntimeError("Use a fresh ThreadPoolExecutor in a with block inside this execution")
            if event == "call" and frame.f_code is _THREAD_START:
                self._enroll(frame.f_locals["self"])
            if event == "c_call":
                if arg is builtins.input:
                    self.execution.request_cancel("input_required")
                    checkpoint()
                if (getattr(arg, "__module__", None) == "_thread"
                        and getattr(arg, "__name__", "") in {
                            "start_new_thread", "start_joinable_thread"}
                        and frame.f_code is not _THREAD_START):
                    raise RuntimeError("Use threading.Thread or mcp.spawn(), not unmanaged _thread workers")
            if (event == "call" and frame.f_code.co_name in {"read", "readline", "readlines"}
                    and frame.f_locals.get("self") is sys.stdin):
                self.execution.request_cancel("input_required")
                checkpoint()
            user_frame = self._user_frame(frame)
            boundary = (frame.f_back is not None and self._user_frame(frame.f_back)
                        and (event == "call" or (event == "return" and
                             frame.f_code.co_name not in {"__enter__", "__exit__", "__del__"})))
            if event in {"call", "return", "c_call", "c_return"} and (user_frame or boundary):
                checkpoint()

        try:
            sys.settrace(trace)
            sys.setprofile(profile)
            yield
        finally:
            sys.settrace(previous_trace)
            sys.setprofile(previous_profile)

    def _enroll(self, thread):
        with self._lock:
            if thread in self._children or thread.ident is not None:
                return
            if self._started_threads >= MAX_CHILD_THREADS:
                raise RuntimeError(f"An execution can start at most {MAX_CHILD_THREADS} Python threads")
            self.execution.checkpoint()
            original_run = thread.run
            self._children[thread] = False
            self._started_threads += 1
            with self.execution.lock:
                self.execution.active_children += 1

            def run():
                try:
                    with self.tracing():
                        self.execution.checkpoint()
                        original_run()
                except InputRequired as exc:
                    self.execution.request_cancel("input_required")
                    self.execution.capture_error(exc)
                except (ExecutionCancelled, KeyboardInterrupt):
                    self.execution.request_cancel()
                except BaseException as exc:
                    self.execution.capture_error(exc)
                    self.execution.request_cancel("child_error")
                finally:
                    thread.run = original_run
                    self._child_finished(thread)

            thread.run = run

    def _child_finished(self, thread):
        with self._lock:
            if not self._children[thread]:
                self._children[thread] = True
                with self.execution.lock:
                    self.execution.active_children -= 1

    def spawn(self, target, *args, **kwargs):
        """Start a child that cannot outlive its owning execution's terminal state."""
        self.execution.checkpoint()
        thread = threading.Thread(target=target, args=args, kwargs=kwargs, daemon=True)
        self._enroll(thread)
        thread.start()
        return thread

    def join(self):
        """Drain every child, including grandchildren registered during the wait.

        Cancellation stays pending while a child is in uninterruptible native
        work. Do not throw out of this drain and falsely release the view lease.
        """
        self.require_owner_thread()
        while True:
            with self._lock:
                children = tuple(self._children)
            for thread in children:
                if thread.ident is None:
                    # Thread.start() failed; there is no worker to join.
                    self._child_finished(thread)
                else:
                    thread.join(0.02)
            if time.monotonic() >= self.execution.deadline:
                self.execution.request_cancel("timeout")
            with self._lock:
                if len(children) == len(self._children) and all(not t.is_alive() for t in children):
                    self._children.clear()
                    self._managed_pools.clear()
                    return

    def require_owner_thread(self):
        if threading.get_ident() != self._owner_thread:
            raise RuntimeError("Undo groups and child draining must run on the interpreter thread")

    def require_transaction_boundary(self):
        self.require_owner_thread()
        with self._lock:
            if any(not pool._shutdown for pool in self._managed_pools):
                raise RuntimeError("Nest ThreadPoolExecutor inside undo_group, so workers close before commit")
