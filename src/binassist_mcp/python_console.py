"""Managed, complete scripts on Binary Ninja's native interpreter thread.

Cancellation is cooperative. A native call may outlive its deadline, and its
execution remains busy until the interpreter actually finishes. No asynchronous
exception is injected into native code or interpreter bookkeeping.
"""

from __future__ import annotations

import ast
import builtins
import ctypes
import linecache
import math
import reprlib
import sys
import threading
import time
import uuid
from collections import OrderedDict

from .analysis_helpers import ScriptHelpers, analysis_state
from .execution import DEFAULT_OUTPUT_BYTES, Execution, ExecutionCancelled, InputRequired
from .execution_scope import ExecutionScope
from .logging import log


DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_TIMEOUT_SECONDS = 600.0
MAX_SOURCE_BYTES = 1_000_000
MAX_HISTORY = 8


class BinaryNinjaPythonConsole:
    """One persistent namespace with at most one live execution."""

    _stdio_lock = threading.Lock()
    _stdio_users = 0
    _stdio_previous = None
    _stdio_installed = None
    # stdio and third-party redirect_stdout contexts are process-global. Hold
    # this through startup, payload, child drain and native interpreter cleanup.
    _execution_lock = threading.Lock()

    def __init__(self):
        # Native initialization, including startup.py, runs outside caller locks.
        self._lock = threading.RLock()
        self._closed = False
        self._instance = None
        self._native_instance = None
        self._listener = None
        self._stdio_registered = False
        self._current_view = None
        self._current_address = None
        self._active = None
        self._history = OrderedDict()
        self.namespace_id = uuid.uuid4().hex
        self._script_builtins = dict(vars(builtins), input=self._reject_input)
        self._script_builtins.pop("_", None)

    def _reject_input(self, prompt=""):
        if self._active is not None:
            self._active.request_cancel("input_required")
        raise InputRequired("Interactive input is unavailable; supply values in code")

    @property
    def busy(self):
        with self._lock:
            return self._active is not None and not self._active.done.is_set()

    @staticmethod
    def _validate_timeout(value):
        try:
            timeout = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("timeout_seconds must be a number") from exc
        if not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError("timeout_seconds must be finite, greater than 0 and at most 600")
        return timeout

    @staticmethod
    def _validate_source(source):
        if not isinstance(source, str) or not source.strip():
            raise ValueError("code must be a nonempty string")
        if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
            raise ValueError("code exceeds the 1 MB source budget")

    def start(self, binary_view, source, address=None, timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
              mode="script", max_output_bytes=DEFAULT_OUTPUT_BYTES, function_start=None,
              architecture=None, cancel_event=None, submitted_at=None):
        submitted_at = time.monotonic() if submitted_at is None else submitted_at
        timeout = self._validate_timeout(timeout_seconds)
        self._validate_source(source)
        if mode not in ("script", "repl"):
            raise ValueError("mode must be script or repl")
        with self._lock:
            if self._closed:
                raise RuntimeError("Python session is closed")
            if self.busy:
                return self.busy_result()
            execution = Execution(timeout, max_output_bytes, created=submitted_at)
            execution.context.update(namespace_id=self.namespace_id, namespace_created=not self._history)
            self._active = execution
            self._history[execution.id] = execution
            while len(self._history) > MAX_HISTORY:
                expired, _ = self._history.popitem(last=False)
                linecache.cache.pop(f"<binassist:{expired}>", None)
            threading.Thread(target=self._run,
                             args=(execution, binary_view, source, address, mode,
                                   function_start, architecture, cancel_event),
                             name=f"binassist-python-{execution.id[:8]}", daemon=True).start()
            return execution

    def busy_result(self):
        return {"success": False, "status": "busy", "still_running": True,
                "execution_id": self._active.id,
                "message": "Previous Python execution is still active"}

    def execute(self, binary_view, source, address=None, timeout_seconds=DEFAULT_TIMEOUT_SECONDS, **options):
        execution = self.start(binary_view, source, address, timeout_seconds, **options)
        return execution if isinstance(execution, dict) else self.wait(execution)

    @staticmethod
    def wait(execution):
        if not execution.done.wait(max(0, execution.deadline - time.monotonic())):
            execution.request_cancel("timeout")
            execution.done.wait(0.05)
        return execution.snapshot()

    def get_execution(self, execution_id):
        with self._lock:
            if execution_id not in self._history:
                raise KeyError("Execution not found in this session (history retains the last 8)")
            return self._history[execution_id]

    def status(self, execution_id, **options):
        return self.get_execution(execution_id).snapshot(**options)

    def cancel(self, execution_id):
        execution = self.get_execution(execution_id)
        execution.request_cancel()
        return execution.snapshot(include_streams=False)

    def _ensure_native(self):
        if self._instance is not None:
            if self._native_instance is None or self._listener is None:
                raise RuntimeError("Native interpreter initialization failed; reset this Python session")
            if not self._native_instance.interpreter.is_alive():
                raise RuntimeError("Native interpreter exited; reset this Python session")
            return
        import binaryninja as bn
        from binaryninja import scriptingprovider as sp
        from binaryninja.enums import ScriptingProviderInputReadyState

        self._bn = bn
        self._headless = not bool(bn.core_ui_enabled())
        self._input_state = ScriptingProviderInputReadyState
        with self._stdio_lock:
            output_type = getattr(sp, "_PythonScriptingInstanceOutput", None)
            if output_type is None:
                raise RuntimeError("Unsupported Binary Ninja Python output bridge")
            cls = type(self)
            if cls._stdio_users == 0 and not isinstance(sys.stdout, output_type):
                cls._stdio_previous = (sys.stdin, sys.stdout, sys.stderr, sys.excepthook)
                sp.redirect_stdio()
                cls._stdio_installed = (sys.stdin, sys.stdout, sys.stderr, sys.excepthook)
            if not self._stdio_registered:
                cls._stdio_users += 1
                self._stdio_registered = True
        self._instance = sp.ScriptingProvider["Python"].create_instance()
        if self._instance is None:
            raise RuntimeError("Cannot create native Python interpreter")
        pointer = ctypes.cast(self._instance.handle, ctypes.c_void_p).value
        for candidate in tuple(getattr(sp.PythonScriptingInstance, "_registered_instances", ())):
            if ctypes.cast(candidate.handle, ctypes.c_void_p).value == pointer:
                self._native_instance = candidate
                break
        if self._native_instance is None:
            self._instance.stop()
            self._instance = None
            raise RuntimeError("Unsupported Binary Ninja scripting API: native namespace unavailable")
        console = self

        class Listener(sp.ScriptingOutputListener):
            def notify_output(self, text):
                console._capture("stdout", text)

            def notify_warning(self, text):
                console._capture("warning", text)

            def notify_error(self, text):
                console._capture("stderr", text)

            def notify_input_ready_state_changed(self, state):
                execution = console._active
                if execution is None:
                    return
                if state == console._input_state.ReadyForScriptExecution:
                    execution.native_ready.set()
                elif state == console._input_state.ReadyForScriptProgramInput:
                    execution.request_cancel("input_required")
                    execution.input_ready.set()

        self._listener = Listener()
        self._instance.register_output_listener(self._listener)

    def _capture(self, stream, text):
        execution = self._active
        if execution is not None and not execution.done.is_set():
            execution.output.append(stream, text)
            if stream == "stderr" and not execution.payload_running:
                with execution.lock:
                    execution.bridge_error = True
                    if execution.error is None:
                        from .execution import bounded_text
                        message = text.decode("utf-8", errors="replace") if isinstance(text, bytes) else str(text)
                        execution.error = {"type": "NativeConsoleError", "message": bounded_text(message, 2048),
                                           "traceback": bounded_text(message, 16384)}

    def _default_address(self, view):
        if self._bn.core_ui_enabled() and isinstance(getattr(view, "offset", None), int):
            return view.offset
        if self._current_view is view and self._current_address is not None:
            return self._current_address
        return int(getattr(view, "entry_point", getattr(view, "start", 0)))

    def _resolve_address(self, view, address):
        if address is None or not str(address).strip():
            return self._default_address(view)
        try:
            value = int(str(address).strip(), 0)
        except ValueError:
            value = view.parse_expression(str(address), self._default_address(view))
        if type(value) is not int or not 0 <= value < 2**64:
            raise ValueError("Address must resolve to an unsigned 64-bit integer")
        return value

    def _set_context(self, view, address, function_start, architecture):
        resolved = self._resolve_address(view, function_start if address is None and function_start is not None else address)
        if function_start is not None:
            candidates = list(view.get_functions_at(self._resolve_address(view, function_start)))
        else:
            candidates = list(view.get_functions_containing(resolved))
        if architecture:
            candidates = [f for f in candidates if f.arch.name == architecture]
        if len(candidates) > 1:
            choices = ", ".join(f"{hex(f.start)} ({f.arch.name})" for f in candidates[:16])
            raise ValueError(f"Ambiguous function; specify function_start/architecture: {choices}")
        if (function_start is not None or architecture) and not candidates:
            raise ValueError("No function matches the requested context")
        function = candidates[0] if candidates else None
        block = function.get_basic_block_at(resolved) if function is not None else None
        self._instance.set_current_binary_view(view)
        self._instance.set_current_address(resolved)
        self._instance.set_current_selection(resolved, resolved)
        self._instance.set_current_function(function)
        self._instance.set_current_basic_block(block)
        self._current_view, self._current_address = view, resolved
        return {"address": hex(resolved), "function": getattr(function, "name", None),
                "function_start": hex(function.start) if function is not None else None,
                "architecture": getattr(getattr(function or view, "arch", None), "name", None)}

    @staticmethod
    def _compile(source, filename, mode):
        if mode == "repl":
            tree = compile(source + "\n", filename, "single", ast.PyCF_ONLY_AST, dont_inherit=True)

            class DisplayExpressions(ast.NodeTransformer):
                def visit_Expr(self, node):
                    return ast.copy_location(ast.Expr(value=ast.Call(
                        func=ast.Name(id="__binassist_display__", ctx=ast.Load()),
                        args=[node.value], keywords=[])), node)

                # These scopes are not interactive, even inside a REPL command.
                def visit_FunctionDef(self, node):
                    return node

                visit_AsyncFunctionDef = visit_FunctionDef
                visit_ClassDef = visit_FunctionDef

            tree = ast.Module(body=DisplayExpressions().visit(tree).body, type_ignores=[])
            return compile(ast.fix_missing_locations(tree), filename, "exec", dont_inherit=True)
        tree = ast.parse(source, filename=filename, mode="exec")
        if tree.body and isinstance(tree.body[-1], ast.Expr):
            last = tree.body[-1]
            tree.body[-1] = ast.copy_location(ast.Expr(value=ast.Call(
                func=ast.Name(id="__binassist_display__", ctx=ast.Load()),
                args=[last.value], keywords=[],)), last)
        return compile(ast.fix_missing_locations(tree), filename, "exec", dont_inherit=True)

    def _run(self, execution, view, source, address, mode, function_start, architecture, cancel_event):
        acquired = False
        try:
            with execution.lock:
                if not execution.cancel_event.is_set():
                    execution.status = "queued"
            while not self._execution_lock.acquire(timeout=0.02):
                if cancel_event is not None and cancel_event.is_set():
                    execution.request_cancel()
                execution.checkpoint()
            acquired = True
            self._run_serialized(execution, view, source, address, mode,
                                 function_start, architecture, cancel_event)
        except (ExecutionCancelled, InputRequired):
            execution.finish("cancelled")
        except BaseException as exc:
            execution.capture_error(exc)
            execution.finish("error")
        finally:
            if acquired:
                self._execution_lock.release()
            if self._closed:
                self._dispose_native()

    def _run_serialized(self, execution, view, source, address, mode, function_start, architecture, cancel_event):
        filename = f"<binassist:{execution.id}>"
        try:
            linecache.cache[filename] = (len(source), None, source.splitlines(keepends=True), filename)
            code = self._compile(source, filename, mode)
            execution.checkpoint()
            self._ensure_native()
            if cancel_event is not None and cancel_event.is_set():
                execution.request_cancel()
            execution.checkpoint()
            execution.context.update(self._set_context(view, address, function_start, architecture))
            execution.analysis_at_start = analysis_state(view)
            namespace = self._native_instance.interpreter.locals
            namespace["__binassist_run__"] = lambda: self._execute_payload(execution, view, code)
            from binaryninja.enums import ScriptingProviderExecuteResult
            with execution.lock:
                execution.checkpoint()
                execution.started = time.monotonic()
                execution.status = "running"
            execution.native_ready.clear()
            result = self._instance.execute_script_input("__binassist_run__()\n")
            if result != ScriptingProviderExecuteResult.SuccessfulScriptExecution:
                raise RuntimeError("Native interpreter rejected the complete script")
            while not execution.native_ready.wait(0.02):
                if cancel_event is not None and cancel_event.is_set():
                    execution.request_cancel()
                if time.monotonic() >= execution.deadline:
                    execution.request_cancel("timeout")
                if execution.input_ready.is_set():
                    execution.input_ready.clear()
                    self._instance.execute_script_input("\n")
                if not self._native_instance.interpreter.is_alive():
                    raise RuntimeError("Native interpreter exited during execution; reset the session")
            execution.analysis = analysis_state(view)
            execution.finish("error" if execution.bridge_error else (execution.script_status or "error"))
        except (ExecutionCancelled, InputRequired) as exc:
            if isinstance(exc, InputRequired):
                execution.request_cancel("input_required")
            execution.finish("cancelled")
        except BaseException as exc:
            execution.capture_error(exc)
            execution.finish("error")
            if self._native_instance is None:
                self._release_stdio()
        finally:
            if self._closed:
                self._dispose_native()

    def _execute_payload(self, execution, view, code):
        execution.payload_running = True
        namespace = self._native_instance.interpreter.locals
        previous_stdio = sys.stdin, sys.stdout, sys.stderr
        scope = ExecutionScope(execution)
        formatter = reprlib.Repr()
        formatter.maxstring = formatter.maxother = 4096
        formatter.maxlist = formatter.maxtuple = formatter.maxdict = 30

        def display(value):
            if value is not None:
                namespace["_"] = value
                execution.output.append("stdout", formatter.repr(value) + "\n")

        namespace["__builtins__"] = self._script_builtins
        namespace["mcp"] = ScriptHelpers(execution, view, scope)
        namespace["__binassist_display__"] = display
        try:
            execution.checkpoint()
            with scope.tracing():
                exec(code, namespace, namespace)
            execution.checkpoint()
            execution.script_status = "ok"
        except InputRequired as exc:
            execution.request_cancel("input_required")
            execution.capture_error(exc)
            execution.script_status = "input_required"
        except (ExecutionCancelled, KeyboardInterrupt):
            execution.request_cancel()
            execution.script_status = "cancelled"
        except BaseException as exc:
            execution.capture_error(exc)
            execution.script_status = "error"
        finally:
            scope.join()
            sys.stdin, sys.stdout, sys.stderr = previous_stdio
            try:
                if self._headless:
                    interpreter = self._native_instance.interpreter
                    changed = [name for name in ("here", "current_address")
                               if namespace.get(name) != interpreter.cached_locals.get(name)]
                    if changed:
                        resolved = self._resolve_address(view, namespace[changed[-1]])
                        interpreter.current_addr = interpreter.active_addr = resolved
                        interpreter.current_selection_begin = interpreter.active_selection_begin = resolved
                        interpreter.current_selection_end = interpreter.active_selection_end = resolved
                        self._current_address = resolved
                        for name in ("here", "current_address"):
                            namespace[name] = interpreter.cached_locals[name] = resolved
                        execution.context["address"] = hex(resolved)
                        functions = list(view.get_functions_containing(resolved))
                        function = functions[0] if len(functions) == 1 else None
                        execution.context["function"] = getattr(function, "name", None)
                        execution.context["function_start"] = hex(function.start) if function is not None else None
                namespace.pop("mcp", None)
                namespace.pop("__binassist_display__", None)
                namespace.pop("__binassist_run__", None)
                namespace["__builtins__"] = self._script_builtins
            except BaseException as exc:
                execution.capture_error(exc)
                execution.script_status = "error"
            execution.payload_running = False

    def close(self):
        with self._lock:
            self._closed = True
            if self.busy:
                self._active.request_cancel()
                return False
        self._dispose_native()
        return True

    def _dispose_native(self):
        with self._lock:
            instance, native, listener = self._instance, self._native_instance, self._listener
            self._instance = self._native_instance = self._listener = None
            self._current_view = None
            for execution_id in self._history:
                linecache.cache.pop(f"<binassist:{execution_id}>", None)
            self._history.clear()
            self._active = None
        if instance is not None:
            try:
                if listener is not None:
                    instance.unregister_output_listener(listener)
                instance.stop()
                if native is not None:
                    native.interpreter.join(timeout=1)
                    if not native.interpreter.is_alive():
                        native.interpreter.locals.clear()
                        native.interpreter.cached_locals.clear()
                        native.interpreter.current_view = native.interpreter.active_view = None
                        native.interpreter.current_func = native.interpreter.active_func = None
                        native.interpreter.current_block = native.interpreter.active_block = None
            except Exception as exc:
                log.log_debug(f"Python session cleanup failed: {exc}")
        self._release_stdio()

    def _release_stdio(self):
        with self._stdio_lock:
            if self._stdio_registered:
                cls = type(self)
                self._stdio_registered = False
                cls._stdio_users -= 1
                if cls._stdio_users == 0 and cls._stdio_previous is not None:
                    for name, previous, installed in zip(
                            ("stdin", "stdout", "stderr", "excepthook"),
                            cls._stdio_previous, cls._stdio_installed):
                        if getattr(sys, name) is installed:
                            setattr(sys, name, previous)
                    cls._stdio_previous = cls._stdio_installed = None
