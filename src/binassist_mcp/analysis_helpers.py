"""Opt-in, bounded helpers exposed as ``mcp`` inside Python scripts."""

from contextlib import contextmanager
import ctypes
import uuid


def native_identity(value):
    """Compare native wrappers while their owning views remain retained."""
    handle = getattr(value, "handle", None)
    if handle is not None:
        return ("native", ctypes.cast(handle, ctypes.c_void_p).value)
    return ("python", id(value))


def analysis_state(view):
    """Report analysis freshness separately from script completion."""
    try:
        state = view.analysis_progress.state
        name = getattr(state, "name", str(state))
        try:
            aborted = bool(view.analysis_is_aborted)
        except (AttributeError, RuntimeError):
            aborted = None
        idle = name == "IdleState"
        return {"state": name, "idle": idle, "aborted": aborted,
                "complete": idle and aborted is False,
                "completeness": "queue_state_only"}
    except Exception:
        return {"state": "unknown", "idle": False, "aborted": None,
                "complete": False, "completeness": "unknown"}


class FunctionSnapshot:
    """Frozen membership with compact locators, not retained Function/IL objects.

    The source view stays alive so its native identity cannot be reused. Re-fetch
    each requested function after reanalysis; a removed function is an explicit
    stale-snapshot error instead of silently shifting subsequent page offsets.
    """

    def __init__(self, view, records):
        self._view = view
        self.records = tuple(records)
        self.id = uuid.uuid4().hex

    def __len__(self):
        return len(self.records)

    def __repr__(self):
        return f"<FunctionSnapshot {self.id}: {len(self)} functions>"

    def get(self, view, index):
        if native_identity(view) != native_identity(self._view):
            raise ValueError("Function snapshot belongs to a different BinaryView")
        import binaryninja as bn
        platform, address = self.records[index]
        function = view.get_function_at(address, plat=bn.Platform[platform] if platform else None)
        if function is None:
            raise RuntimeError(f"Function snapshot is stale at {address:#x}; create a new snapshot")
        return function


class ScriptHelpers:
    def __init__(self, execution, view, scope=None):
        self._execution = execution
        self._view = view
        self._scope = scope
        self._functions = None

    def spawn(self, target, *args, **kwargs):
        """Start a managed thread; the execution waits for it and its children."""
        if self._scope is None:
            raise RuntimeError("This helper has no managed execution scope")
        return self._scope.spawn(target, *args, **kwargs)

    def checkpoint(self, progress=None, message=None):
        """Check cancellation/deadline and optionally publish bounded progress."""
        self._execution.checkpoint(progress, message)

    def emit(self, value):
        """Publish a JSON record (256 records / 64 KiB per execution)."""
        self._execution.emit(value)

    def write(self, text, stream="stdout"):
        """Capture explicit output, including from child threads."""
        self._execution.write(text, stream)

    def _function_list(self):
        self.checkpoint()
        if self._functions is None:
            self._functions = self._view.functions
        return self._functions

    def function_snapshot(self, max_functions=250_000):
        """Freeze locators once for paging across scripts (at most 1M functions)."""
        if type(max_functions) is not int or not 1 <= max_functions <= 1_000_000:
            raise ValueError("max_functions must be between 1 and 1000000")
        functions = self._function_list()
        if len(functions) > max_functions:
            raise ValueError("Function snapshot budget exceeded; raise max_functions or use indexed batches")
        records = []
        for function in functions:
            self.checkpoint()
            records.append((getattr(function.platform, "name", None), function.start))
        return FunctionSnapshot(self._view, records)

    def functions(self, offset=0, limit=100, snapshot=None):
        """Index a bounded batch; pass a FunctionSnapshot for cross-script paging."""
        if not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be nonnegative")
        if not isinstance(limit, int) or not 1 <= limit <= 10_000:
            raise ValueError("limit must be between 1 and 10000")
        if snapshot is not None and not isinstance(snapshot, FunctionSnapshot):
            raise ValueError("snapshot must come from mcp.function_snapshot()")
        functions = snapshot if snapshot is not None else self._function_list()
        for index in range(offset, min(offset + limit, len(functions))):
            self.checkpoint()
            yield snapshot.get(self._view, index) if snapshot is not None else functions[index]

    def function_status(self, function):
        self.checkpoint()
        reason = getattr(function, "analysis_skip_reason", None)
        return {"address": hex(function.start), "name": function.name,
                "analysis_skipped": bool(getattr(function, "analysis_skipped", False)),
                "skip_reason": getattr(reason, "name", str(reason)),
                "too_large": bool(getattr(function, "too_large", False))}

    def get_il(self, function, level="hlil", generate=False):
        """Use cached IL by default; generating IL is explicit."""
        if level not in ("llil", "mlil", "hlil"):
            raise ValueError("level must be llil, mlil or hlil")
        self.checkpoint()
        value = getattr(function, level if generate else level + "_if_available")
        self.checkpoint()
        return value

    def walk_il(self, instruction, max_nodes=10_000):
        """Visit nested expressions iteratively with cycle and size guards."""
        if not isinstance(max_nodes, int) or not 1 <= max_nodes <= 100_000:
            raise ValueError("max_nodes must be between 1 and 100000")
        pending, seen = [instruction], set()
        while pending:
            self.checkpoint()
            node = pending.pop()
            key = (id(getattr(node, "function", None)), getattr(node, "expr_index", id(node)))
            if key in seen:
                continue
            if len(seen) >= max_nodes:
                raise ValueError("IL traversal node budget exceeded")
            seen.add(key)
            yield node
            children = []
            for operand in getattr(node, "operands", ()):
                values = operand if isinstance(operand, (list, tuple)) else (operand,)
                for value in values:
                    if hasattr(value, "operation"):
                        children.append(value)
                        if len(pending) + len(children) > max_nodes:
                            raise ValueError("IL traversal queue budget exceeded")
            pending.extend(reversed(children))

    def wait_for_analysis(self):
        """Wait on the interpreter thread; a native wait may outlive cancellation."""
        self.checkpoint()
        if analysis_state(self._view)["aborted"]:
            raise RuntimeError("Analysis is aborted; resume the workflow before waiting for completion")
        self._view.update_analysis_and_wait()
        self.checkpoint()
        self._execution.analysis = analysis_state(self._view)
        if not self._execution.analysis["complete"]:
            raise RuntimeError("Analysis did not complete; inspect mcp.analysis_status()")
        return dict(self._execution.analysis)

    def analysis_status(self):
        self.checkpoint()
        return analysis_state(self._view)

    @contextmanager
    def undo_group(self):
        """Revert supported database edits on failure, not filesystem effects.

        Opt-in: avoid concurrent UI editing while this group is open.
        """
        self.checkpoint()
        if self._scope is not None:
            self._scope.require_transaction_boundary()
        token = self._view.begin_undo_actions()
        try:
            yield
            if self._scope is not None:
                self._scope.join()
            self.checkpoint()
        except BaseException:
            if self._scope is not None:
                self._scope.join()
            self._view.revert_undo_actions(token)
            raise
        else:
            self._view.commit_undo_actions(token)
