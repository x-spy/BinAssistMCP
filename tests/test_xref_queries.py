"""Reference pagination must bound work as well as rendered output."""

from types import SimpleNamespace as NS

import pytest

from binassist_mcp import function_context as fc
from binassist_mcp import xref_queries as xq
from tests.test_function_queries import FakeFunction, FakeView


class Indexed:
    def __init__(self, count, item):
        self.count, self.item = count, item
        self.reads, self.closed = [], False

    def __len__(self):
        return self.count

    def __getitem__(self, index):
        assert 0 <= index < self.count
        assert not self.closed
        self.reads.append(index)
        return self.item(index)

    def __iter__(self):
        raise AssertionError("Must not materialize whole native lists")

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class References:
    def __init__(self, view, function):
        self.view, self.function = view, function
        self.arrays, self.calls = [], []
        self.incoming_count, self.site_count, self.caller_count = 0, 0, 0
        self.targets, self.call_targets = {}, {}

    def array(self, count, item):
        array = Indexed(count, item)
        self.arrays.append(array)
        return array

    def ref(self, index):
        return NS(address=0x800 + index * 2, function=self.function, arch=self.function.arch)

    def incoming(self, address, calls=False):
        self.calls.append(("callers" if calls else "incoming", address))
        return self.array(self.caller_count if calls else self.incoming_count, self.ref)

    def outgoing(self, function, arch, address, calls=False):
        assert function is self.function and arch.name == "thumb2"
        self.calls.append(("callees" if calls else "outgoing", address))
        targets = (self.call_targets if calls else self.targets).get(address, ())
        return self.array(len(targets), targets.__getitem__)

    def call_sites(self, function):
        self.calls.append(("sites", function.start))
        return self.array(self.site_count, self.ref)


@pytest.fixture
def query(monkeypatch):
    view = FakeView()
    function = FakeFunction(view, 0x200)
    function.basic_blocks = [NS(start=0x200, end=0x206, arch=function.arch)]
    view.functions = [function]
    view.analysis_info = NS(analysis_time=0)
    view.modified = False
    view.length_reads = []
    function.arch.get_instruction_text = lambda data, address: (view.length_reads.append(address) or [], 2)
    view.get_instruction_length = lambda address, arch: 6  # can group Thumb IT instructions
    references = References(view, function)
    monkeypatch.setattr(xq, "NativeReferences", lambda v: references)
    monkeypatch.setattr(fc, "current_ui_selection", lambda v: fc.UISelection(0x200, function, "ui_selection"))
    return view, function, references


def pages(view, **options):
    cursor = None
    for _ in range(100):
        page = xq.xref_page(view, "0x200", cursor=cursor, **options)
        assert page["success"], page
        assert xq._wire_size(page) <= options.get("max_output_bytes", 32768)
        yield page
        if not page["has_more"]:
            return
        assert page["next_cursor"] != cursor
        cursor = page["next_cursor"]
    raise AssertionError("Pagination did not terminate")


def test_35233_outgoing_refs_do_not_materialize_or_render_all_targets(query):
    view, function, refs = query
    refs.targets[function.start] = range(0x1000, 0x1000 + 35233)
    page = xq.xref_page(view, "0x200", direction="from")
    assert page["success"] and 0 < page["returned"] <= 100
    assert page["has_more"] and page["call_graph"] is None
    assert page["streams"]["references_from"]["total"] is None
    assert refs.arrays[0].reads in [list(range(page["returned"])), list(range(page["returned"] + 1))]
    assert all(array.closed for array in refs.arrays)
    assert xq._wire_size(page) <= 32768
    assert not view.length_reads  # still inside the first instruction's fanout
    assert not any(kind in {"sites", "callers", "callees"} for kind, _ in refs.calls)
    second = xq.xref_page(view, "0x200", direction="from", cursor=page["next_cursor"])
    assert second["references_from"][0]["to_address"] == hex(0x1000 + page["returned"])
    assert refs.arrays[1].reads[0] == page["returned"]


def test_resume_across_fanout_instructions_and_blocks_has_no_duplicates_or_gaps(query):
    view, function, refs = query
    function.basic_blocks.append(NS(start=0x300, end=0x302, arch=function.arch))
    refs.targets = {0x200: range(0x1000, 0x1017), 0x204: [0x4000], 0x300: [0x5000, 0x6000]}
    results = list(pages(view, direction="from", limit=7, scan_limit=10))
    edges = [(row["from_address"], row["to_address"]) for page in results for row in page["references_from"]]
    expected = [(hex(source), hex(target)) for source, targets in refs.targets.items() for target in targets]
    assert edges == expected
    assert results[-1]["streams"]["references_from"]["total"] == len(expected)
    assert results[-1]["complete"]
    assert view.length_reads == [0x200, 0x202, 0x204, 0x300]


def test_sparse_function_obeys_scan_budget_and_resumes_without_prefix_scan(query):
    view, function, refs = query
    blocks = Indexed(100000, lambda i: NS(start=0x200 + i * 2, end=0x202 + i * 2, arch=function.arch))
    function.basic_blocks = blocks
    first = xq.xref_page(view, "0x200", direction="from", scan_limit=12)
    assert first["returned"] == 0 and first["has_more"] and not first["complete"]
    assert first["stop_reason"] == "scan_limit" and first["scanned"] == 12
    assert len(blocks.reads) <= 12
    before = len(view.length_reads)
    second = xq.xref_page(view, "0x200", direction="from", scan_limit=12, cursor=first["next_cursor"])
    assert second["next_cursor"] != first["next_cursor"]
    assert min(view.length_reads[before:]) > max(view.length_reads[:before])


def test_all_streams_share_global_budget_and_calls_remain_optional(query):
    view, function, refs = query
    refs.incoming_count = refs.caller_count = 35233
    refs.site_count = 35233
    refs.targets[0x200] = range(10000)
    refs.call_targets[0x800] = range(10000)
    page = xq.xref_page(view, "0x200", include_calls=True, limit=12)
    assert page["success"] and page["returned"] == 12
    assert all(info["returned"] == 3 for info in page["streams"].values())
    assert page["streams"]["references_to"]["total"] == 35233
    assert page["streams"]["callers"]["total"] == 35233
    assert sum(len(a.reads) for a in refs.arrays) <= 15
    assert all(a.closed for a in refs.arrays)
    assert page["call_graph"]["callers"][0]["call_site"] == "0x800"


def test_calls_include_external_targets_and_multiple_sites(query):
    view, function, refs = query
    refs.site_count = 2
    refs.call_targets = {0x800: [0x9000, 0x9002], 0x802: [0x9000]}
    results = list(pages(view, direction="to", include_calls=True, limit=2))
    calls = [row for page in results for row in page["call_graph"]["callees"]]
    assert [(row["call_site"], row["address"]) for row in calls] == [
        ("0x800", "0x9000"), ("0x800", "0x9002"), ("0x802", "0x9000")]
    assert all(row["name"] is None for row in calls)  # no Function object is required


def test_incoming_only_does_not_walk_function_or_generate_call_graph(query):
    view, function, refs = query
    refs.incoming_count = 35233
    page = xq.xref_page(view, "0x200", direction="to", limit=3)
    assert page["returned"] == 3 and page["streams"]["references_to"]["total"] == 35233
    assert refs.calls == [("incoming", 0x200)]
    assert refs.arrays[0].reads == [0, 1, 2]
    assert function.generated == view.updates == 0


def test_byte_budget_counts_utf8_escaping_metadata_and_cursor(query):
    view, function, refs = query
    function.name = '中文\\"\n' * 10000
    refs.targets = {0x200: [function.start] * 20}
    result = list(pages(view, direction="from", max_output_bytes=4096, limit=100))
    assert sum(page["returned"] for page in result) == 20
    assert any(page["details_truncated"] for page in result)
    assert all(xq._wire_size(page) <= 4096 for page in result)


def test_cursor_pins_function_and_rejects_wrong_query_view_or_changed_analysis(query, monkeypatch):
    view, function, refs = query
    refs.targets = {0x200: [0x1000, 0x1002]}
    first = xq.xref_page(view, "0x200", direction="from", limit=1)
    other = FakeFunction(view, 0x300)
    view.functions.append(other)
    monkeypatch.setattr(fc, "current_ui_selection", lambda v: fc.UISelection(0x200, other, "ui_selection"))
    second = xq.xref_page(view, "0x200", direction="from", limit=1, cursor=first["next_cursor"])
    assert second["function_start"] == "0x200" and second["references_from"][0]["to_address"] == "0x1002"
    assert xq.xref_page(view, "0x202", direction="from", cursor=first["next_cursor"])["status"] == "cursor_mismatch"
    assert xq.xref_page(FakeView(), "0x200", direction="from", cursor=first["next_cursor"])["status"] == "cursor_mismatch"
    view.analysis_info.analysis_time += 1
    assert xq.xref_page(view, "0x200", direction="from", cursor=first["next_cursor"])["status"] == "stale_cursor"
    assert xq.xref_page(view, "0x200", cursor="bad cursor")["status"] == "invalid_cursor"


def test_explicit_address_scope_does_not_scan_the_containing_function(query):
    view, function, refs = query
    refs.targets = {0x200: [0x1000], 0x204: [0x1002, 0x1004]}
    page = xq.xref_page(view, "0x204", direction="from", scope="address")
    assert page["complete"] and page["scope"] == "address"
    assert [row["to_address"] for row in page["references_from"]] == ["0x1002", "0x1004"]
    assert not view.length_reads and refs.calls == [("outgoing", 0x204)]


def test_cursor_rejects_an_expression_that_resolves_to_a_different_address(query):
    view, _, refs = query
    refs.targets = {0x200: [0x1000, 0x1002], 0x204: [0x2000, 0x2002]}
    view.parse_expression = lambda expression: 0x200
    first = xq.xref_page(view, "here", direction="from", scope="address", limit=1)
    view.parse_expression = lambda expression: 0x204
    second = xq.xref_page(view, "here", direction="from", scope="address", cursor=first["next_cursor"])
    assert second["status"] == "stale_cursor"


def test_invalid_instruction_is_explicit_and_native_arrays_are_closed(query):
    view, function, refs = query
    function.arch.get_instruction_text = lambda *args: None
    page = xq.xref_page(view, "0x200", direction="from")
    assert page["status"] == "invalid_instruction" and not page["success"]
    assert all(a.closed for a in refs.arrays)


@pytest.mark.parametrize("option,value", [("limit", 0), ("limit", 1001), ("limit", True),
                                         ("max_output_bytes", 4095), ("scan_limit", 10001),
                                         ("direction", "invalid"), ("scope", "invalid")])
def test_invalid_options_fail_before_native_access(query, option, value):
    view, _, refs = query
    with pytest.raises(ValueError):
        xq.xref_page(view, "0x200", **{option: value})
    assert not refs.calls


def test_native_array_frees_once_on_exception():
    freed = []
    with pytest.raises(RuntimeError):
        with xq.NativeArray([1, 2, 3], 3, freed.append) as array:
            assert array[1] == 2
            raise RuntimeError("conversion failed")
    array.close()
    assert freed == [[1, 2, 3]]


def test_native_reference_adapter_accepts_both_supported_core_signatures():
    def legacy(view, address, count):
        return view, address, count

    def current(view, address, count, has_max_items, max_items):
        assert has_max_items is False and max_items == 0
        return view, address, count

    for function in (legacy, current):
        assert xq._code_references(NS(BNGetCodeReferences=function), "view", 0, "count") == ("view", 0, "count")
