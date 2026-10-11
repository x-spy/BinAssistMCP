"""Native regressions for mixed ISA decoding and non-mutating IL queries."""

import asyncio
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
