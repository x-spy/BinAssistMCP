"""Bounded, explicitly labelled views of existing analysis results."""

import hashlib
import json

from .analysis_helpers import analysis_state, native_identity
from .execution import bounded_text
from .function_context import ContextResolutionError, function_key, parse_address


def integer(name, value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer between {low} and {high}")


def json_size(value):
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8"))


def function_state(function):
    reason = getattr(function, "analysis_skip_reason", None)
    return {"analysis_skipped": bool(function.analysis_skipped),
            "skip_reason": getattr(reason, "name", str(reason)),
            "too_large": bool(function.too_large),
            "needs_update": bool(function.needs_update)}


def base_result(context, view):
    return {"success": True, "status": "ok", **context.metadata(),
            "address": hex(context.function.start), "analysis": analysis_state(view),
            "function_analysis": function_state(context.function)}


def _snapshot(context, representation, content):
    return hashlib.sha256(repr((function_key(context.function), representation, content)).encode()).hexdigest()[:24]


def _check_snapshot(expected, actual):
    if expected is not None and expected != actual:
        raise ContextResolutionError("stale_page", "Analysis/representation changed; restart pagination at offset 0")


def _get_il(context, view, format, generate, force_analysis):
    function = context.function
    if force_analysis and not generate:
        raise ValueError("force_analysis requires generate=true")
    if generate and analysis_state(view)["aborted"]:
        raise ContextResolutionError("analysis_aborted", "Resume the analysis workflow before requesting generation")
    if force_analysis:
        function.analysis_skipped = False
        view.update_analysis_and_wait()
    if generate and function.analysis_skipped:
        return None, None, "analysis_skipped"
    levels = ("hlil", "mlil") if format == "decompile" else ("hlil",) if format == "pseudo_c" else (format,)
    for level in levels:
        il = getattr(function, level if generate else level + "_if_available")
        if il is not None:
            return il, level, None
    return None, None, "il_unavailable"


def code_page(view, context, *, format="decompile", offset=0, limit=100,
              max_output_bytes=16384, generate=False, force_analysis=False,
              full_render=False, snapshot_id=None):
    integer("offset", offset, 0, 2**63 - 1)
    integer("limit", limit, 1, 1000)
    integer("max_output_bytes", max_output_bytes, 4096, 262144)
    if format not in {"decompile", "pseudo_c", "hlil", "mlil", "llil", "disasm"}:
        raise ValueError("format must be decompile, pseudo_c, hlil, mlil, llil or disasm")
    if format == "disasm" and (generate or force_analysis or full_render):
        raise ValueError("Disassembly reads existing instructions; generation/full_render options apply only to IL")
    result = base_result(context, view)
    result.update(format=format, code=None, offset=offset, complete=False, truncated=False,
                  has_more=False, next_offset=None, generation_requested=generate,
                  force_analysis_requested=force_analysis)
    function = context.function
    if format == "disasm":
        if snapshot_id is not None:
            raise ValueError("snapshot_id applies to IL pages; restart disassembly paging after analysis changes")
        # Iterating native blocks follows actual instruction boundaries and the
        # block's ISA. Never decode every byte using the view's default arch.
        rows, index = [], 0
        for block in function.basic_blocks:
            address = block.start
            for tokens, length in block:
                if index >= offset:
                    raw_text = "".join(token.text for token in tokens)
                    text = bounded_text(raw_text, 8192)
                    row = {"index": index, "address": hex(address), "architecture": block.arch.name,
                           "text": text, "text_truncated": text != raw_text}
                    trial = {**result, "instructions": rows + [row], "code": "\n".join(r["text"] for r in rows + [row])}
                    if len(rows) >= limit or (rows and json_size(trial) > max_output_bytes - 512):
                        result.update(has_more=True, next_offset=index)
                        break
                    while json_size(trial) > max_output_bytes - 512:
                        row.update(text=row["text"][:len(row["text"]) // 2], text_truncated=True)
                        trial.update(instructions=[row], code=row["text"])
                    rows.append(row)
                    result["truncated"] |= row["text_truncated"]
                index += 1
                address += length
            if result["has_more"]:
                break
        result.update(representation="disassembly_instructions", offset_unit="instruction",
                      instructions=rows, code="\n".join(r["text"] for r in rows),
                      complete=offset == 0 and not result["has_more"] and not result["truncated"],
                      pagination_consistency="requires_unchanged_analysis")
        return result

    il, level, unavailable = _get_il(context, view, format, generate, force_analysis)
    result["function_analysis"] = function_state(function)
    result["analysis"] = analysis_state(view)
    if unavailable:
        result.update(success=False, status=unavailable, message=(
            "Cached IL is unavailable. Pass generate=true to request generation; "
            "changing a skipped function additionally requires force_analysis=true."))
        return result
    result["il_level"] = level
    representation = None
    if format == "pseudo_c":
        representation = getattr(function, "pseudo_c" if generate else "pseudo_c_if_available")
        if representation is None:
            result.update(success=False, status="il_unavailable", message="Pseudo C representation is not cached; use generate=true")
            return result

    if full_render:
        # Explicitly opted in: native whole-function formatting can be costly.
        text = ("\n".join(str(line) for line in representation.get_linear_lines(il.root))
                if representation is not None else str(il) if level == "hlil"
                else "\n".join(str(il[i]) for i in range(len(il))))
        identity = _snapshot(context, "full_" + format, hashlib.sha256(text.encode()).hexdigest())
        _check_snapshot(snapshot_id, identity)
        result.update(snapshot_id=identity, representation="full_render_page", offset_unit="character",
                      total_characters=len(text), native_formatting="whole_function")
        page = bounded_text(text[offset:offset + limit], max_output_bytes - json_size(result) - 512)
        while json_size({**result, "code": page}) > max_output_bytes - 128:
            page = page[:len(page) // 2]
        end = offset + len(page)
        result.update(code=page, has_more=end < len(text), next_offset=end if end < len(text) else None,
                      complete=offset == 0 and end >= len(text))
        return result

    identity = _snapshot(context, level, (native_identity(il), len(il)))
    _check_snapshot(snapshot_id, identity)
    result.update(snapshot_id=identity, representation="pseudo_c_instruction_fragments" if representation else level + "_instruction_fragments",
                  offset_unit="instruction", total_instructions=len(il), instructions=[],
                  note="Native non-AST instruction fragments; this is not a complete structured function listing.")
    texts = []
    for index in range(offset, min(offset + limit, len(il))):
        instruction = il[index]
        text = ("\n".join(str(line) for line in representation.get_expr_text(instruction, None))
                if representation is not None else str(instruction))
        captured = bounded_text(text, 8192)
        row = {"index": index, "address": hex(instruction.address),
               "operation": instruction.operation.name, "text": captured,
               "text_truncated": captured != text}
        trial = {**result, "instructions": result["instructions"] + [row],
                 "code": "\n".join(texts + [captured])}
        if json_size(trial) > max_output_bytes - 256 and result["instructions"]:
            break
        while json_size(trial) > max_output_bytes - 256:
            captured = captured[:len(captured) // 2]
            row.update(text=captured, text_truncated=True)
            trial.update(instructions=[row], code=captured)
        result["instructions"].append(row)
        texts.append(captured)
        result["truncated"] |= row["text_truncated"]
    end = offset + len(result["instructions"])
    result.update(code="\n".join(texts), has_more=end < len(il), next_offset=end if end < len(il) else None,
                  complete=offset == 0 and end >= len(il) and not result["truncated"])
    return result


def _edge_page(edges, offset, limit, direction):
    items = []
    for edge in edges[offset:offset + limit]:
        block = edge.source if direction == "incoming" else edge.target
        items.append({"address": hex(block.start) if block is not None else None,
                      "architecture": block.arch.name if block is not None else None,
                      "type": getattr(edge.type, "name", str(edge.type))})
    end = min(len(edges), offset + limit)
    return items, {"total": len(edges), "offset": offset,
                   "next_offset": end if end < len(edges) else None,
                   "complete": offset == 0 and end == len(edges)}


def block_page(view, context, *, offset=0, limit=50, block_address=None,
               edge_offset=0, edge_limit=16, max_output_bytes=32768):
    integer("offset", offset, 0, 2**63 - 1)
    integer("limit", limit, 1, 500)
    integer("edge_offset", edge_offset, 0, 2**63 - 1)
    integer("edge_limit", edge_limit, 1, 256)
    integer("max_output_bytes", max_output_bytes, 4096, 262144)
    function = context.function
    blocks = function.basic_blocks
    total = len(blocks)
    if block_address is not None:
        block = function.get_basic_block_at(parse_address(view, block_address))
        if block is None:
            raise ContextResolutionError("block_not_found", "No block in the selected function contains block_address")
        blocks = [block]
    result = base_result(context, view)
    result.update(blocks=[], scope="block" if block_address is not None else "function",
                  total_blocks=total, matching_blocks=len(blocks), offset=offset,
                  next_offset=None, has_more=False, complete=False, truncated=False,
                  pagination_consistency="requires_unchanged_analysis")
    for index in range(offset, min(offset + limit, len(blocks))):
        block = blocks[index]
        incoming, outgoing = block.incoming_edges, block.outgoing_edges
        row = {"index": index, "start": hex(block.start), "end": hex(block.end),
               "architecture": block.arch.name, "length": block.length,
               "instruction_count": block.instruction_count}
        row["predecessors"], row["predecessors_page"] = _edge_page(incoming, edge_offset, edge_limit, "incoming")
        row["successors"], row["successors_page"] = _edge_page(outgoing, edge_offset, edge_limit, "outgoing")
        if json_size({**result, "blocks": result["blocks"] + [row]}) > max_output_bytes - 256:
            if result["blocks"]:
                break
            # Preserve a usable edge cursor even when one high-degree node fills a page.
            while json_size({**result, "blocks": [row]}) > max_output_bytes - 256:
                field = max(("predecessors", "successors"), key=lambda key: len(row[key]))
                row[field] = row[field][:len(row[field]) // 2]
                row[field + "_page"].update(next_offset=edge_offset + len(row[field]), complete=False)
            result["truncated"] = True
        result["blocks"].append(row)
    end = offset + len(result["blocks"])
    edges_complete = all(row["predecessors_page"]["complete"] and row["successors_page"]["complete"] for row in result["blocks"])
    result.update(next_offset=end if end < len(blocks) else None, has_more=end < len(blocks),
                  edges_complete=edges_complete,
                  complete=offset == 0 and end >= len(blocks) and edges_complete and not result["truncated"])
    return result


def function_summary(view, context, *, block_offset=0, block_limit=500):
    integer("block_offset", block_offset, 0, 2**63 - 1)
    integer("block_limit", block_limit, 1, 5000)
    function = context.function
    blocks = function.basic_blocks
    end = min(block_offset + block_limit, len(blocks))
    instruction_count, edges, branches, exits = 0, 0, 0, []
    exit_count = 0
    for index in range(block_offset, end):
        block = blocks[index]
        instruction_count += block.instruction_count
        outgoing = block.outgoing_edges
        edges += len(outgoing)
        branches += len(outgoing) > 1
        if not outgoing:
            exit_count += 1
            if len(exits) < 32:
                exits.append(hex(block.start))
    complete = block_offset == 0 and end == len(blocks)
    result = base_result(context, view)
    result.update(name=bounded_text(function.name, 256), size=function.total_bytes, basic_block_count=len(blocks),
                  lowest_address=hex(function.lowest_address), highest_address=hex(function.highest_address),
                  complete=complete, instruction_count=instruction_count if complete else None,
                  block_scan={"offset": block_offset, "count": max(0, end - block_offset),
                              "next_offset": end if end < len(blocks) else None,
                              "instruction_count": instruction_count, "edge_count": edges,
                              "branch_block_count": branches, "exit_block_count": exit_count,
                              "exit_block_sample": exits, "exit_sample_complete": exit_count <= len(exits)},
                  complexity={"cyclomatic_estimate": edges - len(blocks) + 2 if complete else None,
                              "assumption": "one connected CFG component; unresolved edges may affect the estimate"},
                  note="Counts in block_scan cover only that page. Call depth and loop count are not inferred from call-site counts or address ordering.")
    return result
