"""Context, read-only analysis and pagination regressions without a GUI."""

import json
from types import SimpleNamespace as NS

import pytest

from binassist_mcp import function_context as fc
from binassist_mcp import tools as tool_module
from binassist_mcp.analysis_queries import block_page, code_page, function_summary
from binassist_mcp.python_console import BinaryNinjaPythonConsole


class FakeIL:
    def __init__(self, count=5):
        self.count, self.reads, self.full_reads = count, [], 0

    def __len__(self):
        return self.count

    def __getitem__(self, index):
        self.reads.append(index)
        class Instruction:
            address = 0x100 + index * 2
            operation = NS(name="HLIL_CMP_E")

            def __str__(self):
                return "中文cmp r0, r11 " * 8
        return Instruction()

    def __str__(self):
        self.full_reads += 1
        return "complete native rendering\n" * 20


class FakeFunction:
    def __init__(self, view, start, arch="thumb2", platform="linux-thumb2"):
        self.view, self.start = view, start
        self.name = f"sub_{start:x}"
        self.arch = NS(name=arch, max_instr_length=4)
        self.arch.get_instruction_text = lambda data, address: ([NS(text="cmp r0, r11")], 2)
        self.platform = NS(name=platform)
        self.lowest_address, self.highest_address = 0x100, start + 4
        self.total_bytes = 12
        self.analysis_skipped, self.too_large, self.needs_update = True, True, False
        self.analysis_skip_reason = NS(name="ExceedFunctionSizeSkipReason")
        self.basic_blocks = []
        self.hlil_if_available = FakeIL()
        self.mlil_if_available = self.llil_if_available = None
        self.generated = 0

    @property
    def hlil(self):
        self.generated += 1
        return self.hlil_if_available or FakeIL()

    def get_basic_block_at(self, address):
        return next((b for b in self.basic_blocks if b.start <= address < b.end), None)

    def get_instruction_containing_address(self, address, arch):
        assert arch is self.arch
        return address & ~1


class FakeView:
    def __init__(self):
        self.functions = []
        self.offset = 0x120
        self.arch = NS(name="armv7")
        self.analysis_progress = NS(state=NS(name="IdleState"))
        self.analysis_is_aborted = False
        self.updates = 0

    def get_functions_at(self, address):
        return [f for f in self.functions if f.start == address]

    def get_functions_containing(self, address):
        return list(self.functions) if 0x100 <= address < 0x500 else []

    def get_functions_by_name(self, name):
        return [f for f in self.functions if f.name == name]

    def parse_expression(self, expression):
        raise ValueError(expression)

    def get_symbol_at(self, address):
        return None

    def get_segment_at(self, address):
        return None

    def read(self, address, count):
        return b"\x58\x45\x70\x47"[:count]

    def update_analysis_and_wait(self):
        self.updates += 1


@pytest.fixture
def sample(monkeypatch):
    view = FakeView()
    wrong = FakeFunction(view, 0x300)
    selected = FakeFunction(view, 0x200)
    view.functions = [wrong, selected]
    ui = fc.UISelection(0x120, selected, "ui_selection")
    monkeypatch.setattr(fc, "current_ui_selection", lambda view: ui)
    monkeypatch.setattr(tool_module, "current_ui_selection", lambda view: ui)
    monkeypatch.setattr(tool_module, "BINJA_AVAILABLE", True)
    return view, selected, ui


def test_selected_overlap_controls_current_function_and_instruction(sample):
    view, function, _ = sample
    tools = tool_module.BinAssistMCPTools(view)
    result = tools.get_current_function()
    assert result["function"]["address"] == "0x200"
    assert result["candidate_count"] == 2
    result = tools.get_current_address()
    assert result["disassembly"] == "cmp r0, r11"
    assert result["architecture"] == "thumb2"
    assert "end" not in result["in_function"]
    assert "offset_in_function" not in result["in_function"]


def test_interior_address_uses_ui_but_explicit_entry_overrides_it(sample):
    view, selected, _ = sample
    assert fc.resolve_function(view, "0x120").function is selected
    assert fc.resolve_function(view, "0x300").function is view.functions[0]
    assert fc.resolve_function(view, "0x120", function_start="0x300").function is view.functions[0]
    assert fc.resolve_function(view, "sub_200").function is selected
    with pytest.raises(fc.ContextResolutionError, match="outside"):
        fc.resolve_function(view, "0x600", function_start="0x200")


def test_ambiguity_is_structured_and_never_selects_first(sample, monkeypatch):
    view, _, _ = sample
    monkeypatch.setattr(fc, "current_ui_selection", lambda view: fc.UISelection(0x120))
    result = tool_module.BinAssistMCPTools(view).get_code("0x120")
    assert result["status"] == "ambiguous_function"
    assert result["candidate_count"] == 2
    assert len(result["candidates"]) == 2


def test_foreign_ui_selection_and_unavailable_cursor_are_not_used(sample, monkeypatch):
    view, _, _ = sample
    other_view = FakeView()
    foreign = FakeFunction(other_view, 0x200)
    with pytest.raises(fc.ContextResolutionError, match="Ambiguous"):
        fc.resolve_function(view, "0x120", ui=fc.UISelection(0x120, foreign))
    monkeypatch.setattr(tool_module, "current_ui_selection", lambda view: fc.UISelection(reason="No UI"))
    result = tool_module.BinAssistMCPTools(view).get_current_address()
    assert result["status"] == "context_unavailable" and result["address"] is None


def test_architecture_and_platform_disambiguate_same_entry(sample):
    view, selected, _ = sample
    alternate = FakeFunction(view, selected.start, "armv7", "linux-armv7")
    view.functions.append(alternate)
    assert fc.resolve_function(view, "0x200", architecture="armv7").function is alternate
    assert fc.resolve_function(view, "0x200", platform="linux-thumb2").function is selected


def frame_for(view, function, address=0x120):
    location = NS(isValid=lambda: True, getFunction=lambda: function, getOffset=lambda: address)
    interface = NS(getCurrentFunction=lambda: function)
    return NS(getCurrentBinaryView=lambda: view, getViewLocation=lambda: location,
              getCurrentViewInterface=lambda: interface)


def test_unique_visible_ui_is_used_when_bn_is_not_foreground(sample):
    view, function, _ = sample
    frame = frame_for(view, function)
    ctx = NS(getCurrentViewFrame=lambda: frame, getTabs=lambda: [frame])
    api = NS(activeContext=lambda: None, allContexts=lambda: [ctx])
    selection = fc._read_ui_selection(view, api)
    assert selection.function is function and selection.source == "ui_visible_view"
    frame2 = frame_for(view, view.functions[0])
    ctx2 = NS(getCurrentViewFrame=lambda: frame2, getTabs=lambda: [frame2])
    api.allContexts = lambda: [ctx, ctx2]
    assert fc._read_ui_selection(view, api).address is None


def test_existing_il_reads_do_not_generate_or_clear_skip(sample):
    view, function, _ = sample
    context = fc.resolve_function(view, "0x120")
    result = code_page(view, context, limit=2)
    assert result["representation"] == "hlil_instruction_fragments"
    assert result["has_more"] and result["next_offset"] == 2
    assert not result["complete"]
    assert function.hlil_if_available.reads == [0, 1]
    assert function.generated == function.hlil_if_available.full_reads == view.updates == 0
    assert function.analysis_skipped
    page = code_page(view, context, offset=2, limit=3, snapshot_id=result["snapshot_id"])
    assert [i["index"] for i in page["instructions"]] == [2, 3, 4]
    assert page["next_offset"] is None
    function.hlil_if_available = FakeIL(6)
    with pytest.raises(fc.ContextResolutionError, match="changed"):
        code_page(view, context, offset=2, snapshot_id=result["snapshot_id"])


def test_generation_and_force_are_separate_choices(sample):
    view, function, _ = sample
    context = fc.resolve_function(view, "0x120")
    function.hlil_if_available = None
    assert code_page(view, context)["status"] == "il_unavailable"
    assert code_page(view, context, generate=True)["status"] == "analysis_skipped"
    assert function.generated == view.updates == 0
    with pytest.raises(ValueError, match="requires generate"):
        code_page(view, context, force_analysis=True)
    result = code_page(view, context, generate=True, force_analysis=True)
    assert result["success"] and not function.analysis_skipped
    assert function.generated == view.updates == 1


def test_full_render_is_explicit_and_bytes_are_bounded(sample):
    view, function, _ = sample
    context = fc.resolve_function(view, "0x120")
    result = code_page(view, context, limit=2, max_output_bytes=4096)
    assert len(json.dumps(result, ensure_ascii=False).encode()) <= 4096
    assert function.hlil_if_available.full_reads == 0
    result = code_page(view, context, full_render=True, limit=20)
    assert function.hlil_if_available.full_reads == 1
    assert result["offset_unit"] == "character" and result["has_more"]


def make_block(start, incoming=0, outgoing=0):
    block = NS(start=start, end=start + 12, length=12, instruction_count=3, arch=NS(name="thumb2"))
    block.incoming_edges = [NS(source=NS(start=i*2, arch=block.arch), type=NS(name="TrueBranch")) for i in range(incoming)]
    block.outgoing_edges = [NS(target=NS(start=0x900+i*2, arch=block.arch), type=NS(name="FalseBranch")) for i in range(outgoing)]
    return block


def test_high_degree_cfg_is_paged_without_hiding_edges(sample):
    view, function, _ = sample
    function.basic_blocks = [make_block(0x100, incoming=144, outgoing=2), make_block(0x200)]
    context = fc.resolve_function(view, "0x120")
    page = block_page(view, context, limit=1)
    assert page["total_blocks"] == 2 and page["next_offset"] == 1
    assert not page["complete"] and not page["edges_complete"]
    assert len(page["blocks"][0]["predecessors"]) == 16
    assert page["blocks"][0]["predecessors_page"]["total"] == 144
    second = block_page(view, context, block_address="0x100", edge_offset=16, edge_limit=16)
    assert second["blocks"][0]["predecessors"][0]["address"] == "0x20"
    tiny = block_page(view, context, block_address="0x100", edge_limit=256, max_output_bytes=4096)
    assert len(json.dumps(tiny, ensure_ascii=False).encode()) <= 4096
    assert tiny["truncated"] and tiny["blocks"][0]["predecessors_page"]["next_offset"] > 0


def test_summary_does_not_confuse_bytes_with_instructions_or_calls_with_depth(sample):
    view, function, _ = sample
    function.basic_blocks = [make_block(0x100, outgoing=2), make_block(0x200)]
    context = fc.resolve_function(view, "0x120")
    partial = function_summary(view, context, block_limit=1)
    assert partial["instruction_count"] is None
    assert partial["block_scan"]["instruction_count"] == 3
    assert partial["block_scan"]["next_offset"] == 1
    full = function_summary(view, context)
    assert full["instruction_count"] == 6 and full["complete"]
    assert "call_depth" not in full["complexity"]


def test_reference_source_function_is_not_reported_as_callee(sample):
    view, caller, _ = sample
    target = view.functions[0]
    seen = []
    def refs(address, func=None, arch=None):
        seen.append((address, func, arch))
        return [target.start]
    view.get_code_refs_from = refs
    site = NS(address=0x120, function=caller, arch=caller.arch)
    result = tool_module.BinAssistMCPTools(view)._get_call_target_functions(site)
    assert result == [target]
    assert seen == [(0x120, caller, caller.arch)]


def test_signature_decoding_uses_function_arch_and_includes_address_zero(sample):
    from binassist_mcp.function_signature_generator import BinaryNinjaFunctionSignatureGenerator
    view, function, _ = sample
    calls = []
    view.get_instruction_length = lambda addr, arch=None: calls.append(arch) or 2
    view.get_disassembly = lambda addr, arch=None: calls.append(arch) or "cmp r0, r11"
    function.basic_blocks = [NS(disassembly_text=[NS(address=0)])]
    result = BinaryNinjaFunctionSignatureGenerator(view).generate(function)
    assert result == "58 45"
    assert calls == [function.arch, function.arch]
