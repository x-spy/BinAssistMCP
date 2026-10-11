"""Cursor-based reference queries with bounded Python work and wire output.

Binary Ninja returns native reference arrays, not native offset pages. Index
those arrays directly and free them in the same request instead of converting
all entries to Python objects. Outgoing cursors resume at a block/instruction
and target index, including in the middle of a large indirect-branch fanout.
"""

import base64
from contextlib import ExitStack
import ctypes
import hashlib
import hmac
import inspect
import json
import secrets

from .analysis_helpers import analysis_state, native_identity
from .analysis_queries import integer
from .execution import bounded_text
from .function_context import (ContextResolutionError, describe_function, function_key,
                               parse_address, resolve_function)


_CURSOR_KEY = secrets.token_bytes(32)
_STREAMS = ("references_to", "references_from", "callers", "callees")


def _code_references(core, view_handle, address, count):
    # Older supported BN releases predate the optional max-items arguments.
    arguments = (view_handle, address, count)
    if len(inspect.signature(core.BNGetCodeReferences).parameters) >= 5:
        arguments += (False, 0)
    return core.BNGetCodeReferences(*arguments)


class NativeArray:
    """Own a native array; materialize only the requested element."""

    def __init__(self, data, count, free, convert=lambda item: item):
        if data is None:
            raise RuntimeError("Binary Ninja returned no reference array")
        self.data, self.count, self.free, self.convert = data, count, free, convert

    def __len__(self):
        return self.count

    def __getitem__(self, index):
        if not 0 <= index < self.count:
            raise IndexError(index)
        return self.convert(self.data[index])

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        if self.data is not None:
            self.free(self.data)
            self.data = None


class NativeReferences:
    """Small adapter over the same core APIs used by BinaryView/Function."""

    def __init__(self, view):
        from binaryninja import _binaryninjacore as core
        from binaryninja.binaryview import ReferenceSource
        self.view, self.core = view, core
        self.convert = lambda item: ReferenceSource._from_core_struct(view, item)

    def incoming(self, address, calls=False):
        count = ctypes.c_ulonglong()
        core = self.core
        data = (core.BNGetCallers(self.view.handle, address, count) if calls else
                _code_references(core, self.view.handle, address, count))
        return NativeArray(data, count.value,
                           lambda data: core.BNFreeCodeReferences(data, count.value), self.convert)

    def outgoing(self, function, arch, address, calls=False):
        count = ctypes.c_ulonglong()
        core = self.core
        source = core.BNReferenceSource(function.handle, arch.handle, address)
        data = (core.BNGetCallees(self.view.handle, source, count) if calls else
                core.BNGetCodeReferencesFrom(self.view.handle, source, count))
        return NativeArray(data, count.value, core.BNFreeAddressList)

    def call_sites(self, function):
        count = ctypes.c_ulonglong()
        core = self.core
        data = core.BNGetFunctionCallSites(function.handle, count)
        return NativeArray(data, count.value,
                           lambda data: core.BNFreeCodeReferences(data, count.value), self.convert)


def _encode(payload):
    data = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(data).decode() + "." + hmac.new(_CURSOR_KEY, data, "sha256").hexdigest()


def _decode(cursor):
    try:
        if not isinstance(cursor, str) or len(cursor) > 8192:
            raise ValueError()
        encoded, signature = cursor.split(".")
        data = base64.b64decode(encoded, altchars=b"-_", validate=True)
        if not hmac.compare_digest(signature, hmac.new(_CURSOR_KEY, data, "sha256").hexdigest()):
            raise ValueError()
        return json.loads(data)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ContextResolutionError("invalid_cursor", "Invalid/expired xref cursor; restart without cursor") from exc


def _digest(value):
    return hashlib.sha256(repr(value).encode()).hexdigest()[:24]


def _wire_size(result):
    # FastMCP emits indented JSON in one TextContent (no duplicate structured
    # output schema). Include JSON escaping and reserve transport metadata.
    text = json.dumps(result, ensure_ascii=False, indent=2)
    return len(json.dumps({"content": [{"type": "text", "text": text}],
                           "isError": False}, ensure_ascii=False).encode()) + 128


def _stamp(view, function, blocks, address, scope):
    # A cheap change detector, not a frozen database snapshot. Callers must
    # still restart after edits/reanalysis; native APIs provide no read txn.
    return _digest((native_identity(view), native_identity(function) if function else None,
                    function_key(function) if function else None, len(blocks), address, scope,
                    getattr(getattr(view, "analysis_info", None), "analysis_time", None),
                    bool(getattr(view, "modified", False)),
                    bool(getattr(function, "needs_update", False))))


def _target(view, identifier, direction, include_calls, scope, selectors):
    try:
        context = resolve_function(view, identifier, **selectors)
        return context.address, context
    except ContextResolutionError as exc:
        only_address = direction == "to" and not include_calls and scope != "function"
        if (only_address and not any(selectors.values()) and
                exc.details["status"] == "ambiguous_function"):
            return parse_address(view, identifier), None
        if (exc.details["status"] != "function_not_found" or
                scope == "function" or any(selectors.values())):
            raise
        return parse_address(view, identifier), None


def _source_row(ref, *, caller=False):
    function = ref.function
    row = {"address": hex(ref.address), "function": None,
           "function_start": None, "architecture": getattr(ref.arch, "name", None)}
    if function is not None:
        name = bounded_text(function.name, 128)
        row.update(function=name, function_start=hex(function.start),
                   platform=getattr(function.platform, "name", None),
                   details_truncated=name != function.name)
    if caller:
        row.update(name=row["function"], call_site=row["address"], address=row["function_start"])
    return row


def _destination_row(view, address, target, arch, *, callee=False):
    functions = view.get_functions_at(target)
    row = {"from_address": hex(address), "to_address": hex(target),
           "architecture": arch.name, "to_function": None,
           "target_candidates": [], "target_candidate_count": len(functions),
           "ambiguous_target": len(functions) > 1, "details_truncated": len(functions) > 4}
    for function in functions[:4]:
        description = describe_function(function)
        description["name"] = bounded_text(function.name, 128)
        row["details_truncated"] |= description["name"] != function.name
        row["target_candidates"].append(description)
    if len(functions) == 1:
        row["to_function"] = row["target_candidates"][0]["name"]
    if callee:
        row.update(name=row["to_function"], address=hex(target), call_site=hex(address))
    return row


class ReferenceWalker:
    def __init__(self, view, source, context, address, scope):
        self.view, self.source, self.context = view, source, context
        self.function = context.function if context else None
        self.address, self.scope = address, scope
        self.blocks = self.function.basic_blocks if self.function and scope == "function" else []
        self.stack = ExitStack()
        self.arrays, self.target_arrays = {}, {}
        self.block_index, self.block = None, None

    def close(self):
        try:
            for _, array in self.target_arrays.values():
                array.close()
        finally:
            self.stack.close()

    def _array(self, key, factory):
        if key not in self.arrays:
            self.arrays[key] = self.stack.enter_context(factory())
        return self.arrays[key]

    def _targets(self, stream, function, arch, address):
        key = (function_key(function), arch.name, address)
        previous = self.target_arrays.get(stream)
        if previous is None or previous[0] != key:
            if previous:
                previous[1].close()
            self.target_arrays.pop(stream, None)
            array = self.source.outgoing(function, arch, address, calls=stream == "callees")
            self.target_arrays[stream] = key, array
        return self.target_arrays[stream][1]

    def step(self, stream, state):
        """Advance at most one reference, instruction, block, or call site."""
        if stream in {"references_to", "callers"}:
            address = self.function.start if stream == "callers" else self.address
            refs = self._array(stream, lambda: self.source.incoming(address, calls=stream == "callers"))
            state["total"] = len(refs)
            if state["index"] >= len(refs):
                state["done"] = True
                return None
            row = _source_row(refs[state["index"]], caller=stream == "callers")
            state["index"] += 1
            state["done"] = state["index"] == len(refs)
            return row

        if self.function is None:
            state.update(done=True, total=0)
            return None
        if stream == "callees":
            sites = self._array(stream, lambda: self.source.call_sites(self.function))
            if state["index"] >= len(sites):
                state.update(done=True, total=state["count"])
                return None
            site = sites[state["index"]]
            function, arch, address = site.function or self.function, site.arch or self.function.arch, site.address
        elif self.scope == "address":
            if state["index"]:
                state.update(done=True, total=state["count"])
                return None
            function, arch, address = self.function, self.function.arch, self.address
        else:
            if state["index"] >= len(self.blocks):
                state.update(done=True, total=state["count"])
                return None
            if self.block_index != state["index"]:
                self.block_index, self.block = state["index"], self.blocks[state["index"]]
            block = self.block
            function, arch = self.function, block.arch
            address = state["address"] if state["address"] is not None else block.start
            if address >= block.end:
                state.update(index=state["index"] + 1, address=None, ref=0)
                return None
        targets = self._targets(stream, function, arch, address)
        if state["ref"] < len(targets):
            row = _destination_row(self.view, address, targets[state["ref"]], arch, callee=stream == "callees")
            state["ref"] += 1
            return row
        state["ref"] = 0
        if stream == "callees" or self.scope == "address":
            state["index"] += 1
        else:
            # Match BasicBlock's textual instruction boundaries. The core's
            # get_instruction_length can group Thumb IT instructions and skip
            # reference sources inside that group.
            decoded = arch.get_instruction_text(
                self.view.read(address, min(arch.max_instr_length, block.end - address)), address)
            length = decoded[1] if decoded is not None else 0
            if length <= 0 or address + length > block.end:
                raise ContextResolutionError("invalid_instruction", f"Cannot advance xref scan at {address:#x} ({arch.name})")
            state["address"] = address + length
        return None


def xref_page(view, identifier, *, direction="both", include_calls=False, scope="auto",
              function_start=None, architecture=None, platform=None, cursor=None,
              limit=100, max_output_bytes=32768, scan_limit=2000):
    integer("limit", limit, 1, 1000)
    integer("max_output_bytes", max_output_bytes, 4096, 262144)
    integer("scan_limit", scan_limit, 1, 10000)
    if direction not in {"to", "from", "both"}:
        raise ValueError("direction must be to, from or both")
    if scope not in {"auto", "address", "function"}:
        raise ValueError("scope must be auto, address or function")
    if type(include_calls) is not bool:
        raise ValueError("include_calls must be a boolean")
    try:
        return _xref_page(view, identifier, direction, include_calls, scope,
                          function_start, architecture, platform, cursor, limit, max_output_bytes, scan_limit)
    except ContextResolutionError as exc:
        error = dict(exc.details)
        while _wire_size(error) > max_output_bytes and error["candidates"]:
            error["candidates"].pop()
            error["candidates_truncated"] = True
        error["message"] = bounded_text(error["message"], 512)
        return error


def _xref_page(view, identifier, direction, include_calls, scope, function_start,
               architecture, platform, cursor, limit, max_output_bytes, scan_limit):
    request = _digest((str(identifier), direction, include_calls, scope))
    payload = _decode(cursor) if cursor is not None else None
    selectors = dict(function_start=function_start, architecture=architecture, platform=platform)
    if payload:
        if payload["request"] != request or payload["view"] != list(native_identity(view)):
            raise ContextResolutionError("cursor_mismatch", "Cursor belongs to a different view or xref query")
        if payload["function"]:
            pinned = dict(zip(selectors, payload["function"]))
            selectors = {key: value if value is not None else pinned[key] for key, value in selectors.items()}
    address, context = _target(view, identifier, direction, include_calls, scope, selectors)
    function = context.function if context else None
    resolved_scope = ("function" if function else "address") if scope == "auto" else scope
    blocks = function.basic_blocks if function and resolved_scope == "function" else []
    stamp = _stamp(view, function, blocks, address, resolved_scope)
    if payload and payload["stamp"] != stamp:
        raise ContextResolutionError("stale_cursor", "Analysis/function changed; restart xref pagination without cursor")
    requested = [direction in {"to", "both"}, direction in {"from", "both"},
                 include_calls and function is not None, include_calls and function is not None]
    states = (payload["states"] if payload else
              [dict(index=0, address=None, ref=0, count=0, done=not enabled, total=None) for enabled in requested])
    turn = payload["turn"] if payload else 0
    result = {"success": True, "status": "ok", "target": bounded_text(str(identifier), 128),
              "address": hex(address), "direction": direction, "scope": resolved_scope,
              "reference_kind": "code", "include_calls": include_calls,
              "references_to": [], "references_from": [], "call_graph": None,
              "analysis": analysis_state(view), "limit": limit, "scan_limit": scan_limit,
              "max_output_bytes": max_output_bytes, "scanned": 0, "returned": 0,
              "pagination_requires_unchanged_analysis": True,
              "details_truncated": bounded_text(str(identifier), 128) != str(identifier), "streams": {}}
    if context:
        result.update(context.metadata())
        result["function"] = bounded_text(function.name, 128)
        result["details_truncated"] |= result["function"] != function.name
    if include_calls and function is not None:
        result["call_graph"] = {"function": bounded_text(function.name, 128),
                                "address": hex(function.start), "callers": [], "callees": [],
                                "semantics": "native possible call edges, including tail calls/jumps; repeated sites are retained"}
    rows = [result["references_to"], result["references_from"],
            result["call_graph"]["callers"] if result["call_graph"] else [],
            result["call_graph"]["callees"] if result["call_graph"] else []]
    pinned = [hex(function.start), function.arch.name, getattr(function.platform, "name", None)] if function else None

    def finish(reason):
        more = any(not state["done"] for state in states)
        result.update(returned=sum(map(len, rows)), has_more=more, complete=not more,
                      truncated=more or result["details_truncated"], stop_reason=reason)
        for index, stream in enumerate(_STREAMS):
            state = states[index]
            result["streams"][stream] = {"requested": requested[index], "returned": len(rows[index]),
                                         "emitted": state["count"], "total": state["total"],
                                         "complete": state["done"]}
        result["next_cursor"] = _encode(dict(request=request, view=native_identity(view),
                                             function=pinned, stamp=stamp, states=states, turn=turn)) if more else None

    walker = ReferenceWalker(view, NativeReferences(view), context, address, resolved_scope)
    try:
        while any(not state["done"] for state in states):
            if result["scanned"] >= scan_limit or sum(map(len, rows)) >= limit:
                break
            index = turn
            turn = (turn + 1) % len(states)
            if states[index]["done"]:
                continue
            before = dict(states[index])
            row = walker.step(_STREAMS[index], states[index])
            result["scanned"] += 1
            if row is None:
                continue
            states[index]["count"] += 1
            rows[index].append(row)
            finish("output_limit")
            if _wire_size(result) > max_output_bytes:
                # Never drop a reference: a too-large first row keeps its edge
                # addresses and counts, while optional labels/candidates shrink.
                if sum(map(len, rows)) == 1:
                    for key in ("target_candidates", "to_function", "function", "name"):
                        if key in row:
                            row[key] = [] if key == "target_candidates" else None
                    row["details_truncated"] = True
                    finish("output_limit")
                if _wire_size(result) > max_output_bytes:
                    rows[index].pop()
                    states[index] = before
                    turn = index
                    if not any(rows):
                        raise ContextResolutionError("output_budget_too_small", "Raise max_output_bytes to fit one xref and its cursor")
                    break
            result["details_truncated"] |= row.get("details_truncated", False)
        reason = ("complete" if all(state["done"] for state in states) else
                  "scan_limit" if result["scanned"] >= scan_limit else
                  "limit" if sum(map(len, rows)) >= limit else "output_limit")
        finish(reason)
        if _stamp(view, function, blocks, address, resolved_scope) != stamp:
            raise ContextResolutionError("stale_cursor", "Analysis changed during the xref query; retry without cursor")
        if _wire_size(result) > max_output_bytes:
            raise ContextResolutionError("output_budget_too_small", "Raise max_output_bytes to fit xref metadata")
        return result
    finally:
        walker.close()
