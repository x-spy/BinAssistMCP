"""Binary Ninja Python console execution support.

This module wraps Binary Ninja's native ``Python`` scripting provider instead
of emulating the console with ``exec``.  Using the provider keeps the MCP tool
aligned with the built-in Python Console: ``startup.py`` is loaded, console
locals persist between calls, magic variables such as ``bv`` and ``here`` are
available, expression values are displayed, and analysis is refreshed after a
command when Binary Ninja's console setting enables it.
"""

from __future__ import annotations

import sys
import threading
import time
from typing import Any, Dict, Optional, Tuple, Union

from .logging import log


DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_TIMEOUT_SECONDS = 600.0
MAX_CAPTURED_OUTPUT_CHARS = 1_000_000


def _set_headless_current_address(instance: Any, old_value: Any, new_value: Any) -> None:
    """Headless-safe setter for the console's here/current_address aliases.

    Binary Ninja's stock setter navigates the UI after assignment. In a
    headless process there is no UI context for that fallback, so update the
    scripting instance's address directly instead.
    """
    interpreter = instance.interpreter
    binary_view = interpreter.active_view
    if binary_view is None:
        return

    if isinstance(new_value, str):
        new_value = binary_view.parse_expression(new_value, interpreter.active_addr)
    if type(new_value) is not int:
        raise ValueError("Can only replace this variable with an integer")

    interpreter.current_addr = new_value
    interpreter.active_addr = new_value
    interpreter.current_selection_begin = new_value
    interpreter.current_selection_end = new_value
    interpreter.active_selection_begin = new_value
    interpreter.active_selection_end = new_value


class _ConsoleOutputBuffer:
    """Thread-safe, size-bounded output collected from a scripting instance."""

    def __init__(self, max_chars: int = MAX_CAPTURED_OUTPUT_CHARS):
        self.max_chars = max_chars
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self.reset()

    @staticmethod
    def _decode(text: Union[str, bytes]) -> str:
        if isinstance(text, bytes):
            return text.decode("utf-8", errors="replace")
        return str(text)

    def reset(self) -> None:
        with self._lock:
            self._events = []
            self._streams = {"stdout": [], "warning": [], "stderr": []}
            self._captured_chars = 0
            self._dropped_chars = 0
        self._ready.clear()

    def append(self, stream: str, text: Union[str, bytes]) -> None:
        decoded = self._decode(text)
        if not decoded:
            return

        with self._lock:
            remaining = max(0, self.max_chars - self._captured_chars)
            captured = decoded[:remaining]
            dropped = len(decoded) - len(captured)

            if captured:
                self._events.append((stream, captured))
                self._streams[stream].append(captured)
                self._captured_chars += len(captured)
            self._dropped_chars += dropped

    def mark_ready(self) -> None:
        self._ready.set()

    def wait_until_ready(self, timeout: float) -> bool:
        return self._ready.wait(timeout)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            output = "".join(text for _, text in self._events)
            stdout = "".join(self._streams["stdout"])
            warning = "".join(self._streams["warning"])
            stderr = "".join(self._streams["stderr"])
            dropped_chars = self._dropped_chars

        if dropped_chars:
            marker = f"\n[output truncated; {dropped_chars} character(s) omitted]\n"
            output += marker

        return {
            "output": output,
            "stdout": stdout,
            "warning": warning,
            "stderr": stderr,
            "truncated": dropped_chars > 0,
            "dropped_chars": dropped_chars,
        }


def _create_output_listener(buffer: _ConsoleOutputBuffer, ready_state: Any):
    """Create a listener subclass after Binary Ninja is available."""
    from binaryninja.scriptingprovider import ScriptingOutputListener

    class CaptureListener(ScriptingOutputListener):
        def notify_output(self, text):
            buffer.append("stdout", text)

        def notify_warning(self, text):
            buffer.append("warning", text)

        def notify_error(self, text):
            buffer.append("stderr", text)

        def notify_input_ready_state_changed(self, state):
            if state == ready_state:
                buffer.mark_ready()

    return CaptureListener()


class BinaryNinjaPythonConsole:
    """Persistent wrapper around Binary Ninja's native Python console."""

    _stdio_lock = threading.Lock()
    _stdio_prepared = False

    def __init__(self):
        try:
            import binaryninja as bn
            from binaryninja.enums import (
                ScriptingProviderExecuteResult,
                ScriptingProviderInputReadyState,
            )
            from binaryninja.scriptingprovider import ScriptingProvider
        except ImportError as exc:
            raise RuntimeError("Binary Ninja Python API is not available") from exc

        self._bn = bn
        self._execute_result = ScriptingProviderExecuteResult
        self._input_state = ScriptingProviderInputReadyState
        self._lock = threading.RLock()
        self._closed = False
        self._current_view = None
        self._current_address: Optional[int] = None
        self._headless = not bool(self._bn.core_ui_enabled())
        self._native_instance = None

        self._ensure_stdio_redirected()
        if self._headless:
            self._prepare_headless_magic_variables()

        try:
            provider = ScriptingProvider["Python"]
        except KeyError as exc:
            raise RuntimeError("Binary Ninja's Python scripting provider is unavailable") from exc

        self._instance = provider.create_instance()
        if self._instance is None:
            raise RuntimeError("Failed to create a Binary Ninja Python console instance")
        if self._headless:
            self._native_instance = self._find_native_instance()

        self._buffer = _ConsoleOutputBuffer()
        self._listener = _create_output_listener(
            self._buffer,
            self._input_state.ReadyForScriptExecution,
        )
        try:
            self._instance.register_output_listener(self._listener)
        except Exception:
            self._instance.stop()
            raise

    @classmethod
    def _ensure_stdio_redirected(cls) -> None:
        """Enable the native scripting-provider output bridge in headless mode."""
        with cls._stdio_lock:
            if cls._stdio_prepared:
                return

            from binaryninja import scriptingprovider

            output_type = getattr(scriptingprovider, "_PythonScriptingInstanceOutput", None)
            already_redirected = output_type is not None and isinstance(sys.stdout, output_type)
            if not already_redirected:
                scriptingprovider.redirect_stdio()

            cls._stdio_prepared = True

    @classmethod
    def _prepare_headless_magic_variables(cls) -> None:
        """Replace UI-only address setters when no UI exists."""
        from binaryninja.scriptingprovider import PythonScriptingProvider

        with cls._stdio_lock:
            for name in ("here", "current_address"):
                magic_variable = PythonScriptingProvider.magic_variables.get(name)
                if magic_variable is not None:
                    try:
                        magic_variable.set_value = _set_headless_current_address
                    except Exception as exc:
                        log.log_debug(
                            f"Unable to install headless setter for {name}: {exc}"
                        )

    def _find_native_instance(self) -> Any:
        """Find the Python instance backing the public core wrapper."""
        try:
            import ctypes
            from binaryninja.scriptingprovider import PythonScriptingInstance

            wrapper_pointer = ctypes.cast(
                self._instance.handle,
                ctypes.c_void_p,
            ).value
            for candidate in reversed(PythonScriptingInstance._registered_instances):
                candidate_pointer = ctypes.cast(
                    candidate.handle,
                    ctypes.c_void_p,
                ).value
                if candidate_pointer == wrapper_pointer:
                    return candidate
        except Exception as exc:
            log.log_debug(f"Unable to access native Python console context: {exc}")
        return None

    def _refresh_headless_context(self, binary_view: Any) -> Optional[Dict[str, Any]]:
        """Read back address assignments made through headless magic variables."""
        if self._native_instance is None:
            self._native_instance = self._find_native_instance()
            if self._native_instance is None:
                return None

        try:
            address = self._native_instance.interpreter.current_addr
            if not isinstance(address, int):
                return None
            self._current_address = address
            function, _ = self._function_and_block(binary_view, address)
            return {
                "address": hex(address),
                "function": getattr(function, "name", None),
            }
        except Exception as exc:
            log.log_debug(f"Unable to refresh headless Python console context: {exc}")
            return None

    def _default_address(self, binary_view: Any) -> int:
        offset = getattr(binary_view, "offset", None)
        try:
            ui_enabled = bool(self._bn.core_ui_enabled())
        except Exception:
            ui_enabled = False
        if ui_enabled and isinstance(offset, int):
            return offset

        entry_point = getattr(binary_view, "entry_point", None)
        if isinstance(entry_point, int):
            return entry_point

        entry_points = getattr(binary_view, "entry_points", None)
        if entry_points:
            first_entry = entry_points[0]
            if isinstance(first_entry, int):
                return first_entry
            start = getattr(first_entry, "start", None)
            if isinstance(start, int):
                return start

        return int(getattr(binary_view, "start", 0))

    def _resolve_address(self, binary_view: Any, address: Optional[str]) -> int:
        if address is None or not str(address).strip():
            try:
                if self._bn.core_ui_enabled():
                    return self._default_address(binary_view)
            except Exception:
                pass
            if self._current_view is binary_view and self._current_address is not None:
                return self._current_address
            return self._default_address(binary_view)

        expression = str(address).strip()
        try:
            resolved = int(expression, 0)
        except ValueError:
            here = (
                self._current_address
                if self._current_view is binary_view and self._current_address is not None
                else self._default_address(binary_view)
            )
            try:
                resolved = binary_view.parse_expression(expression, here)
            except Exception as exc:
                raise ValueError(
                    f"Unable to resolve address expression '{address}': {exc}"
                ) from exc

        if not isinstance(resolved, int) or resolved < 0:
            raise ValueError(f"Address expression did not resolve to a valid address: {address}")
        return resolved

    @staticmethod
    def _function_and_block(binary_view: Any, address: int) -> Tuple[Any, Any]:
        function = None
        try:
            function = binary_view.get_function_at(address)
        except Exception:
            pass

        if function is None:
            try:
                containing = binary_view.get_functions_containing(address)
                if containing:
                    function = containing[0]
            except Exception:
                pass

        block = None
        if function is not None:
            try:
                block = function.get_basic_block_at(address)
            except Exception:
                try:
                    block = next(
                        (
                            candidate
                            for candidate in function.basic_blocks
                            if candidate.start <= address < candidate.end
                        ),
                        None,
                    )
                except Exception:
                    pass

        return function, block

    def _set_console_context(self, binary_view: Any, address: Optional[str]) -> Tuple[int, Any]:
        resolved_address = self._resolve_address(binary_view, address)
        function, block = self._function_and_block(binary_view, resolved_address)

        self._instance.set_current_binary_view(binary_view)
        self._instance.set_current_address(resolved_address)
        self._instance.set_current_selection(resolved_address, resolved_address)
        self._instance.set_current_function(function)
        self._instance.set_current_basic_block(block)

        self._current_view = binary_view
        self._current_address = resolved_address
        return resolved_address, function

    @staticmethod
    def _validate_timeout(timeout_seconds: float) -> float:
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise ValueError("timeout_seconds must be a number") from exc

        if timeout <= 0 or timeout > MAX_TIMEOUT_SECONDS:
            raise ValueError(
                f"timeout_seconds must be greater than 0 and at most {MAX_TIMEOUT_SECONDS:g}"
            )
        return timeout

    @staticmethod
    def _normalize_source(source: str) -> str:
        if not isinstance(source, str):
            raise TypeError("code must be a string")
        if not source.strip():
            raise ValueError("code must not be empty")
        # The native console feeds lines to InteractiveConsole.  A final blank
        # line completes compound statements in the same way as Ctrl+Enter in
        # the UI console.
        return source if source.endswith("\n") else source + "\n"

    def _is_ready(self) -> bool:
        return self._instance.input_ready_state == self._input_state.ReadyForScriptExecution

    def _cancel(self) -> None:
        try:
            # Binary Ninja 5.x exposes a legacy, unused text argument here.
            self._instance.cancel_script_input("")
        except TypeError:
            self._instance.cancel_script_input()

    def execute(
        self,
        binary_view: Any,
        source: str,
        address: Optional[str] = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> Dict[str, Any]:
        """Execute source in the persistent Binary Ninja console namespace."""
        timeout = self._validate_timeout(timeout_seconds)
        normalized_source = self._normalize_source(source)

        with self._lock:
            if self._closed:
                raise RuntimeError("Binary Ninja Python console is closed")

            if not self._is_ready():
                # Resolve context for the response, but do not mutate a native
                # scripting instance while its previous command is still live.
                resolved_address = self._resolve_address(binary_view, address)
                function, _ = self._function_and_block(binary_view, resolved_address)
                return {
                    "success": False,
                    "status": "busy",
                    "address": hex(resolved_address),
                    "function": getattr(function, "name", None),
                    "output": "",
                    "stdout": "",
                    "warning": "",
                    "stderr": (
                        "The Binary Ninja Python console is still executing "
                        "a previous command."
                    ),
                    "truncated": False,
                    "dropped_chars": 0,
                    "timed_out": False,
                    "duration_ms": 0,
                }

            resolved_address, function = self._set_console_context(binary_view, address)
            context = {
                "address": hex(resolved_address),
                "function": getattr(function, "name", None),
            }

            self._buffer.reset()
            start_time = time.monotonic()
            execute_result = self._instance.execute_script_input(normalized_source)

            if execute_result == self._execute_result.IncompleteScriptInput:
                captured = self._buffer.snapshot()
                return {
                    "success": False,
                    "status": "incomplete",
                    **context,
                    **captured,
                    "timed_out": False,
                    "duration_ms": round((time.monotonic() - start_time) * 1000),
                }

            if execute_result != self._execute_result.SuccessfulScriptExecution:
                captured = self._buffer.snapshot()
                return {
                    "success": False,
                    "status": "rejected",
                    **context,
                    **captured,
                    "timed_out": False,
                    "duration_ms": round((time.monotonic() - start_time) * 1000),
                }

            completed = self._buffer.wait_until_ready(timeout)
            timed_out = not completed
            if timed_out:
                log.log_warn(f"Binary Ninja py_exec exceeded {timeout:g}s; requesting cancellation")
                try:
                    self._cancel()
                except Exception as exc:
                    log.log_warn(f"Failed to cancel timed-out py_exec: {exc}")
                # Give the interpreter a short opportunity to report the
                # resulting KeyboardInterrupt and become usable again.
                self._buffer.wait_until_ready(1.0)

            captured = self._buffer.snapshot()
            duration_ms = round((time.monotonic() - start_time) * 1000)
            has_error = bool(captured["stderr"])
            if self._headless:
                refreshed_context = self._refresh_headless_context(binary_view)
                if refreshed_context is not None:
                    context = refreshed_context

            return {
                "success": not timed_out and not has_error,
                "status": "timeout" if timed_out else ("error" if has_error else "ok"),
                **context,
                **captured,
                "timed_out": timed_out,
                "duration_ms": duration_ms,
            }

    def close(self) -> None:
        """Detach the listener and stop the native interpreter thread."""
        with self._lock:
            if self._closed:
                return
            self._closed = True

            try:
                self._instance.unregister_output_listener(self._listener)
            except Exception as exc:
                log.log_debug(f"Failed to unregister Python console listener: {exc}")

            try:
                self._instance.stop()
            except Exception as exc:
                log.log_debug(f"Failed to stop Python console instance: {exc}")
