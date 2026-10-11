"""Resolve function ownership without guessing among overlapping functions.

UI objects are read together on Binary Ninja's main thread. Only a selection
belonging to the requested native BinaryView can influence a query. Explicit
function selectors take precedence, and unresolved ambiguity is actionable data.
"""

from dataclasses import dataclass
from functools import wraps
import threading

from .analysis_helpers import native_identity
from .execution import bounded_text


def function_key(function):
    return (function.start, function.arch.name, getattr(getattr(function, "platform", None), "name", None))


def describe_function(function):
    return {"name": bounded_text(function.name, 256), "address": hex(function.start),
            "start": hex(function.start), "architecture": function.arch.name,
            "platform": getattr(getattr(function, "platform", None), "name", None)}


def context_result(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ContextResolutionError as exc:
            return exc.details
    return wrapped


class ContextResolutionError(ValueError):
    def __init__(self, status, message, candidates=()):
        self.details = {"success": False, "status": status, "message": message,
                        "candidates": [describe_function(f) for f in candidates[:32]],
                        "candidate_count": len(candidates), "candidates_truncated": len(candidates) > 32}
        choices = ", ".join(f"{f.start:#x} ({f.arch.name})" for f in candidates[:8])
        super().__init__(message + (": " + choices if choices else ""))


@dataclass
class UISelection:
    address: int | None = None
    function: object = None
    source: str = "unavailable"
    reason: str | None = None


def _frame_selection(frame, view, source):
    if frame is None:
        return None
    selected_view = frame.getCurrentBinaryView()
    if selected_view is None or native_identity(selected_view) != native_identity(view):
        return None
    location = frame.getViewLocation()
    if not location.isValid():
        return None
    function = location.getFunction()
    interface = frame.getCurrentViewInterface()
    if interface is not None:
        function = interface.getCurrentFunction() or function
    if function is not None and native_identity(function.view) != native_identity(view):
        return None
    return UISelection(int(location.getOffset()), function, source)


def _read_ui_selection(view, ui_context):
    active = ui_context.activeContext()
    if active is not None:
        selected = _frame_selection(active.getCurrentViewFrame(), view, "ui_selection")
        if selected is not None:
            return selected
    # activeContext() can be None while Codex, rather than BN, has focus.
    # A unique visible selection for this view is still an authoritative source.
    contexts = list(ui_context.allContexts())
    selections = []
    for ctx in contexts:
        if ctx is not None:
            selected = _frame_selection(ctx.getCurrentViewFrame(), view, "ui_visible_view")
            if selected is not None:
                selections.append(selected)
    if not selections:
        for ctx in contexts:
            if ctx is not None:
                for frame in ctx.getTabs() or []:
                    selected = _frame_selection(frame, view, "ui_tab")
                    if selected is not None:
                        selections.append(selected)
    unique = {(s.address, function_key(s.function) if s.function is not None else None): s
              for s in selections}
    if len(unique) == 1:
        return next(iter(unique.values()))
    if unique:
        return UISelection(reason="Multiple UI selections for this BinaryView; focus the intended pane or specify a function")
    return UISelection(reason="No UI selection belongs to the requested BinaryView")


def current_ui_selection(view, timeout=2.0):
    try:
        import binaryninja as bn
        if not bn.core_ui_enabled():
            return UISelection(reason="No UI cursor in headless mode; specify an address or function")
        from binaryninjaui import UIContext
    except ImportError:
        return UISelection(reason="Binary Ninja UI is unavailable")
    result, ready = [], threading.Event()

    def read():
        try:
            result.append(_read_ui_selection(view, UIContext))
        except Exception as exc:
            result.append(UISelection(reason=f"Cannot read UI selection: {exc}"))
        finally:
            ready.set()

    if bn.is_main_thread():
        read()
    else:
        action = bn.execute_on_main_thread(read)
        if not ready.wait(timeout):
            return UISelection(reason="Timed out reading the UI selection; specify an address or function")
    return result[0]


def parse_address(view, value):
    if isinstance(value, int) and not isinstance(value, bool):
        address = value
    else:
        text = str(value).strip()
        try:
            address = int(text, 0)
        except ValueError:
            if text.isdecimal():
                address = int(text, 10)
            else:
                try:
                    address = view.parse_expression(text)
                except (ValueError, TypeError) as exc:
                    raise ContextResolutionError("invalid_address", f"Cannot resolve address: {text}") from exc
    if type(address) is not int or not 0 <= address < 2**64:
        raise ContextResolutionError("invalid_address", "Address must resolve to an unsigned 64-bit integer")
    return address


@dataclass
class FunctionContext:
    function: object
    address: int
    source: str
    candidate_count: int

    def metadata(self):
        return {"function": bounded_text(self.function.name, 256), "function_start": hex(self.function.start),
                "architecture": self.function.arch.name,
                "platform": getattr(getattr(self.function, "platform", None), "name", None),
                "requested_address": hex(self.address), "context_source": self.source,
                "candidate_count": self.candidate_count}


def resolve_function(view, identifier=None, *, function_start=None, architecture=None,
                     platform=None, ui=None):
    selection = ui if ui is not None else current_ui_selection(view)
    if selection.function is not None and hasattr(selection.function, "view"):
        if native_identity(selection.function.view) != native_identity(view):
            selection = UISelection(reason="UI function belongs to another BinaryView")
    current = identifier is None or str(identifier).strip() == ""
    address = None
    candidates = []
    source = "explicit_function" if function_start is not None else "exact_entry"
    if current:
        address = (parse_address(view, function_start) if function_start is not None else selection.address)
        if address is None:
            raise ContextResolutionError("context_unavailable", selection.reason or "No UI cursor available")
        if function_start is None and selection.function is not None:
            candidates = list(view.get_functions_containing(address))
            if function_key(selection.function) not in {function_key(f) for f in candidates}:
                candidates.append(selection.function)
            source = selection.source
    else:
        text = str(identifier).strip()
        try:
            address = int(text, 0)
        except ValueError:
            if text.isdecimal():
                address = int(text, 10)
            else:
                candidates = list(view.get_functions_by_name(text))
                if candidates:
                    source = "function_name"
                else:
                    address = parse_address(view, identifier)
    if address is not None:
        address = parse_address(view, address)
    if function_start is not None:
        source = "explicit_function"
        explicit = list(view.get_functions_at(parse_address(view, function_start)))
        if candidates:
            keys = {function_key(f) for f in candidates}
            explicit = [f for f in explicit if function_key(f) in keys]
        candidates = explicit
    elif not candidates:
        address = parse_address(view, address)
        candidates = list(view.get_functions_at(address))
        if not candidates:
            candidates = list(view.get_functions_containing(address))
            source = "containing_function"
    if architecture:
        candidates = [f for f in candidates if f.arch.name == architecture]
    if platform:
        candidates = [f for f in candidates if getattr(f.platform, "name", None) == platform]
    candidates = list({function_key(f): f for f in candidates}.values())
    count = len(candidates)
    if count > 1 and function_start is None and selection.function is not None:
        selected = [f for f in candidates if function_key(f) == function_key(selection.function)]
        if selected:
            candidates, source = selected, selection.source
    if not candidates:
        raise ContextResolutionError("function_not_found", "No function matches the address/name and explicit selectors")
    if len(candidates) != 1:
        raise ContextResolutionError("ambiguous_function",
                                     "Ambiguous function; specify function_start, architecture and/or platform", candidates)
    function = candidates[0]
    if address is None:
        address = function.start
    if function_start is not None and address != function.start:
        containing = {function_key(f) for f in view.get_functions_containing(address)}
        if function_key(function) not in containing:
            raise ContextResolutionError("context_mismatch", "Requested address is outside the explicitly selected function")
    return FunctionContext(function, address, source, count)


def instruction_at(view, address, function):
    """Decode using the selected function, never the BinaryView's default ISA."""
    arch = function.arch
    start = function.get_instruction_containing_address(address, arch)
    if start is None:
        return {"disassembly": None, "disassembly_status": "not_analyzed_instruction",
                "architecture": arch.name}
    data = view.read(start, arch.max_instr_length)
    decoded = arch.get_instruction_text(data, start)
    if decoded is None or decoded[1] <= 0:
        return {"disassembly": None, "disassembly_status": "decode_failed", "architecture": arch.name}
    tokens, length = decoded
    return {"disassembly": "".join(token.text for token in tokens),
            "disassembly_status": "ok", "instruction_address": hex(start),
            "instruction_length": length, "at_instruction_start": start == address,
            "architecture": arch.name}
