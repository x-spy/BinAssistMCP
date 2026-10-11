"""Native regressions for mixed ISA decoding and non-mutating IL queries."""

import asyncio
import json
import os
from types import SimpleNamespace as NS

import pytest

os.environ.setdefault("BN_DISABLE_USER_PLUGINS", "1")
bn = pytest.importorskip("binaryninja")

from binassist_mcp import function_context as fc
from binassist_mcp import tools as tool_module
from binassist_mcp import python_console
from binassist_mcp.context import BinAssistMCPBinaryContextManager
from binassist_mcp.server import BinAssistMCPServer
from binassist_mcp.xref_queries import NativeReferences


@pytest.fixture
def x86_view():
    view = bn.BinaryView.new(bytes.fromhex("55 48 89 e5 31 c0 5d c3"))
    view.platform = bn.Platform["linux-x86_64"]
    view.create_user_function(0)
    view.update_analysis_and_wait()
    return view


def test_thumb_instruction_uses_selected_architecture(monkeypatch):
    view = bn.BinaryView.new(bytes.fromhex("58457047"))
    view.platform = bn.Platform["linux-armv7"]
    view.create_user_function(0, plat=bn.Platform["linux-thumb2"])
    view.update_analysis_and_wait()
    function = view.get_function_at(0, plat=bn.Platform["linux-thumb2"])
    assert function is not None
    selection = fc.UISelection(0, function, "ui_selection")
    monkeypatch.setattr(fc, "current_ui_selection", lambda view: selection)
    monkeypatch.setattr(tool_module, "current_ui_selection", lambda view: selection)
    result = tool_module.BinAssistMCPTools(view).get_current_address()
    assert result["success"] and result["architecture"] == "thumb2"
    assert result["disassembly"].split()[0] == "cmp"
    assert "r11" in result["disassembly"]
    result = tool_module.BinAssistMCPTools(view).get_code("0x0", format="disasm")
    assert result["success"] and len(result["instructions"]) == 2
    assert [row["address"] for row in result["instructions"]] == ["0x0", "0x2"]
    function.add_user_code_ref(0, 2, arch=function.arch)
    view.update_analysis_and_wait()
    refs = tool_module.BinAssistMCPTools(view).xrefs("0x0", direction="from", scope="address")
    assert refs["success"] and refs["references_from"][0]["to_address"] == "0x2"
    assert refs["references_from"][0]["architecture"] == "thumb2"


def test_il_query_preserves_skip_flag_and_has_explicit_generation(x86_view):
    function = x86_view.get_function_at(0)
    function.analysis_skipped = True
    x86_view.update_analysis_and_wait()
    query = tool_module.BinAssistMCPTools(x86_view)
    first = query.get_code("0x0")
    assert function.analysis_skipped
    assert first["status"] in {"ok", "il_unavailable"}
    blocked = query.get_code("0x0", generate=True)
    assert blocked["status"] == "analysis_skipped" and function.analysis_skipped
    generated = query.get_code("0x0", generate=True, force_analysis=True)
    assert generated["success"] and not function.analysis_skipped
    assert generated["representation"] == "hlil_instruction_fragments"
    assert generated["instructions"]
    full = query.get_code("0x0", full_render=True, limit=1000)
    assert full["success"] and full["representation"] == "full_render_page"


def test_native_cfg_and_summary_are_bounded(x86_view):
    query = tool_module.BinAssistMCPTools(x86_view)
    page = query.get_basic_blocks("0x1", limit=1)
    assert page["success"] and page["function_start"] == "0x0"
    assert len(page["blocks"]) == 1
    summary = query.analyze_function("0x1")
    assert summary["instruction_count"] == 5
    assert summary["size"] == 8
    assert "call_depth" not in summary["complexity"]


def test_script_context_uses_ui_selected_function(x86_view, monkeypatch, tmp_path):
    (tmp_path / "startup.py").write_text("from binaryninja import *\n")
    monkeypatch.setattr(bn, "user_directory", lambda: str(tmp_path))
    selection = fc.UISelection(4, x86_view.get_function_at(0), "ui_selection")
    monkeypatch.setattr(python_console, "current_ui_selection", lambda view: selection)
    console = python_console.BinaryNinjaPythonConsole()
    try:
        result = console.execute(x86_view, "mcp.emit({'function':current_function.start,'here':here})")
        assert result["success"]
        assert result["results"] == [{"function": 0, "here": 4}]
        assert result["context_source"] == "ui_selection"
    finally:
        console.close()


def test_registered_query_schemas_and_interior_lookup(x86_view):
    async def scenario():
        manager = BinAssistMCPBinaryContextManager()
        manager.add_binary(x86_view, "sample")
        server = BinAssistMCPServer().create_mcp_server()
        ctx = NS(request_context=NS(lifespan_context=manager, session=object()))
        try:
            code = server._tool_manager.get_tool("get_code")
            assert code.parameters["properties"]["generate"]["default"] is False
            result = await code.run({"filename": "sample", "function_name_or_address": "0x1",
                                     "generate": True, "limit": 2}, context=ctx)
            assert result["success"] and result["function_start"] == "0x0"
            blocks = await server._tool_manager.get_tool("get_basic_blocks").run(
                {"filename": "sample", "function_name_or_address": "0x1", "limit": 1}, context=ctx)
            assert isinstance(blocks, dict) and "blocks" in blocks
        finally:
            manager.clear()
    asyncio.run(scenario())


@pytest.fixture
def call_view():
    # Two direct calls from 0/5 to 0x10, followed by returns.
    view = bn.BinaryView.new(bytes.fromhex("e80b000000e806000000c3909090909090c3"))
    view.platform = bn.Platform["linux-x86_64"]
    view.create_user_function(0)
    view.create_user_function(0x10)
    view.update_analysis_and_wait()
    return view


def test_native_reference_arrays_match_public_api_without_changing_analysis(call_view):
    view = call_view
    function = view.get_function_at(0)
    source = NativeReferences(view)
    before = (view.modified, function.analysis_skipped)
    with source.incoming(0x10) as refs:
        assert [refs[i].address for i in range(len(refs))] == [r.address for r in view.get_code_refs(0x10)]
    with source.call_sites(function) as sites:
        assert [sites[i].address for i in range(len(sites))] == [r.address for r in function.call_sites]
    for calls in (False, True):
        with source.outgoing(function, function.arch, 0, calls=calls) as targets:
            expected = (view.get_callees if calls else view.get_code_refs_from)(0, function, function.arch)
            assert [targets[i] for i in range(len(targets))] == expected == [0x10]
    assert (view.modified, function.analysis_skipped) == before


def test_native_xrefs_continuation_preserves_call_sites_and_counts(call_view):
    query = tool_module.BinAssistMCPTools(call_view)
    before = (call_view.modified, call_view.get_function_at(0).analysis_skipped)
    cursor, references, callees = None, [], []
    for _ in range(15):
        page = query.xrefs("0x0", direction="from", include_calls=True, limit=1, cursor=cursor)
        assert page["success"], page
        assert page["returned"] <= 1
        references.extend(page["references_from"])
        callees.extend(page["call_graph"]["callees"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert cursor is None
    assert [(row["from_address"], row["to_address"]) for row in references] == [("0x0", "0x10"), ("0x5", "0x10")]
    assert [(row["call_site"], row["address"]) for row in callees] == [("0x0", "0x10"), ("0x5", "0x10")]
    assert page["streams"]["references_from"]["total"] == 2
    assert page["streams"]["callees"]["total"] == 2
    assert (call_view.modified, call_view.get_function_at(0).analysis_skipped) == before


def test_registered_xref_schema_and_wire_budget(call_view):
    async def scenario():
        manager = BinAssistMCPBinaryContextManager()
        manager.add_binary(call_view, "sample")
        server = BinAssistMCPServer().create_mcp_server()
        ctx = NS(request_context=NS(lifespan_context=manager, session=object()))
        try:
            tool = server._tool_manager.get_tool("xrefs")
            assert tool.parameters["properties"]["include_calls"]["default"] is False
            assert tool.parameters["properties"]["limit"]["default"] == 100
            result = await tool.run({"filename": "sample", "address_or_name": "0x10",
                                     "direction": "to", "limit": 1, "max_output_bytes": 4096},
                                    context=ctx, convert_result=True)
            from mcp.types import CallToolResult
            wire = CallToolResult(content=result)
            assert len(wire.model_dump_json().encode()) <= 4096
            page = json.loads(wire.content[0].text)
            assert page["success"] and len(page["references_to"]) == 1
            assert page["streams"]["references_to"]["total"] == 2
        finally:
            manager.clear()
    asyncio.run(scenario())


def test_thumb_it_group_does_not_hide_reference_sources():
    view = bn.BinaryView.new(bytes.fromhex("08bf00e070477047"))
    view.platform = bn.Platform["linux-thumb2"]
    view.create_user_function(0)
    view.update_analysis_and_wait()
    function = view.get_function_at(0)
    function.add_user_code_ref(2, 6, arch=function.arch)
    view.update_analysis_and_wait()
    assert view.get_instruction_length(0, function.arch) == 4
    assert function.arch.get_instruction_text(view.read(0, 8), 0)[1] == 2
    result = tool_module.BinAssistMCPTools(view).xrefs("0x0", direction="from")
    assert result["success"] and result["complete"]
    assert any(row["from_address"] == "0x2" and row["to_address"] == "0x6"
               for row in result["references_from"])
