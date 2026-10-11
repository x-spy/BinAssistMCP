import asyncio
import threading
from types import SimpleNamespace

import pytest

from binassist_mcp.execution import ConsoleOutputBuffer, Execution, ExecutionCancelled
from binassist_mcp.python_console import BinaryNinjaPythonConsole
from binassist_mcp.tasks import TaskManager
from binassist_mcp.analysis_helpers import ScriptHelpers


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1, 0, 601])
def test_rejects_invalid_deadlines(value):
    with pytest.raises(ValueError):
        BinaryNinjaPythonConsole._validate_timeout(value)


def test_output_coalesces_small_writes_and_preserves_diagnostics():
    output = ConsoleOutputBuffer(1024)
    for _ in range(20_000):
        output.append("stdout", "x")
    output.append("stderr", "real error")
    snapshot = output.snapshot()
    assert len(output._events) <= 2
    assert snapshot["truncated"]
    assert snapshot["stderr"] == "real error"
    assert snapshot["retained_bytes"] == 1034
    assert snapshot["dropped_chars"] == 20_000 - 1024


def test_output_cursor_and_utf8_boundary():
    output = ConsoleOutputBuffer(1024)
    output.append("stdout", "中文abc")
    first = output.snapshot(limit=4)
    second = output.snapshot(offset=first["next_offset"], limit=5)
    assert first["output"] == "中"
    assert second["output"] == "文ab"
    assert second["next_offset"] == 4


def test_cancel_request_is_not_completion():
    execution = Execution(30, 1024)
    execution.request_cancel()
    assert execution.snapshot()["still_running"]
    with pytest.raises(ExecutionCancelled):
        execution.checkpoint()
    execution.finish("ok")
    assert execution.snapshot()["status"] == "cancelled"
    assert not execution.snapshot()["success"]


def test_structured_results_are_snapshotted_and_bounded():
    execution = Execution(30, 1024)
    value = {"addresses": [1]}
    execution.emit(value)
    value["addresses"].append(2)
    assert execution.snapshot()["results"] == [{"addresses": [1]}]
    with pytest.raises(ValueError):
        execution.emit("x" * 70_000)


def test_task_cancellation_does_not_get_overwritten():
    async def scenario():
        manager = TaskManager()
        gate = asyncio.Event()
        effects = []

        async def work():
            await gate.wait()
            effects.append(1)

        task_id = await manager.submit(work)
        await asyncio.sleep(0)
        assert task_id in manager._running_futures
        assert manager.cancel_task(task_id)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        gate.set()
        assert manager.get_task_status(task_id)["status"] == "cancelled"
        assert not effects
        await manager.close()

    asyncio.run(scenario())


def test_sync_task_remains_active_until_thread_returns():
    async def scenario():
        manager = TaskManager()
        started, finish = threading.Event(), threading.Event()

        def work():
            started.set()
            finish.wait(2)
            return 42

        task_id = await manager.submit(work)
        while not started.is_set():
            await asyncio.sleep(0.005)
        assert manager.cancel_task(task_id)
        assert manager.get_task_status(task_id)["status"] == "cancel_requested"
        finish.set()
        await manager._running_futures[task_id]
        assert manager.get_task_status(task_id)["status"] == "cancelled"
        await manager.close()

    asyncio.run(scenario())


def test_task_capacity_and_owner_isolation():
    async def scenario():
        manager = TaskManager(max_tasks=1)
        event = asyncio.Event()
        task_id = await manager.submit(event.wait, owner="one")
        assert manager.get_task_status(task_id, owner="two")["status"] == "unknown"
        assert not manager.cancel_task(task_id, owner="two")
        with pytest.raises(RuntimeError):
            await manager.submit(event.wait)
        event.set()
        await manager._running_futures[task_id]
        await manager.close()

    asyncio.run(scenario())


def test_bounded_analysis_helpers_walk_nested_cycles_and_default_to_cached_il():
    execution = Execution(30, 1024)
    view = SimpleNamespace(functions=list(range(10)))
    helper = ScriptHelpers(execution, view)
    assert list(helper.functions(offset=3, limit=2)) == [3, 4]
    function = SimpleNamespace(hlil_if_available=None)
    assert helper.get_il(function) is None
    owner = object()
    first = SimpleNamespace(function=owner, expr_index=0, operation="a", operands=[])
    second = SimpleNamespace(function=owner, expr_index=1, operation="b", operands=[first])
    first.operands.append(second)
    assert list(helper.walk_il(first)) == [first, second]
    with pytest.raises(ValueError, match="budget"):
        list(helper.walk_il(first, max_nodes=1))


def test_function_context_requires_disambiguation():
    console = BinaryNinjaPythonConsole()
    first = SimpleNamespace(start=4, name="arm", arch=SimpleNamespace(name="armv7"),
                            get_basic_block_at=lambda address: None)
    second = SimpleNamespace(start=4, name="thumb", arch=SimpleNamespace(name="thumb2"),
                             get_basic_block_at=lambda address: None)
    view = SimpleNamespace(get_functions_at=lambda address: [first, second])
    with pytest.raises(ValueError, match="Ambiguous"):
        console._set_context(view, None, "4", None)
    console._instance = SimpleNamespace(**{
        name: lambda *args: None for name in ("set_current_binary_view", "set_current_address",
                                            "set_current_selection", "set_current_function", "set_current_basic_block")})
    result = console._set_context(view, None, "4", "thumb2")
    assert result["address"] == "0x4" and result["function"] == "thumb"


def test_completed_execution_rejects_late_publication():
    execution = Execution(30, 1024)
    helper = ScriptHelpers(execution, object())
    helper.emit({"before": True})
    helper.write("before")
    execution.finish("ok")
    before = execution.snapshot()
    for update in (lambda: helper.emit({"late": True}), lambda: helper.write("late"),
                   lambda: helper.checkpoint(0.5, "late")):
        with pytest.raises(RuntimeError, match="finished"):
            update()
    execution.output.append("stdout", "late native callback")
    assert execution.snapshot() == before


def test_function_pages_only_construct_requested_functions():
    class IndexedFunctions:
        reads = 0

        def __len__(self):
            return 10000

        def __getitem__(self, index):
            self.reads += 1
            return index

        def __iter__(self):
            raise AssertionError("Paging must not scan from the beginning")

    class View:
        fetches = 0
        indexed = IndexedFunctions()

        @property
        def functions(self):
            self.fetches += 1
            return self.indexed

    view = View()
    helper = ScriptHelpers(Execution(30, 1024), view)
    for offset in range(0, 10000, 100):
        assert list(helper.functions(offset, 100)) == list(range(offset, offset + 100))
    assert view.fetches == 1
    assert view.indexed.reads == 10000


def test_connection_owners_are_uuids_with_weak_lifetimes():
    import gc
    import uuid
    import weakref
    from binassist_mcp.context import BinAssistMCPBinaryContextManager

    class Session:
        pass

    manager = BinAssistMCPBinaryContextManager()
    first = Session()
    key = id(first)
    owner = manager.owner_for(first)
    assert uuid.UUID(hex=owner).hex == owner
    assert manager.owner_for(first) == owner
    reference = weakref.ref(first)
    del first
    gc.collect()
    assert reference() is None and key not in manager._owners
    assert manager.owner_for(Session()) != owner
    # Some adapters cannot be weak-referenced; retaining them prevents reuse.
    adapter = object()
    assert manager.owner_for(adapter) == manager.owner_for(adapter)
    manager.clear()


@pytest.mark.parametrize("aborted, complete", [(True, False), (False, True), (None, False)])
def test_idle_state_is_not_sufficient_for_completion(aborted, complete):
    from binassist_mcp.analysis_helpers import analysis_state
    view = SimpleNamespace(analysis_progress=SimpleNamespace(state=SimpleNamespace(name="IdleState")))
    if aborted is not None:
        view.analysis_is_aborted = aborted
    state = analysis_state(view)
    assert state["idle"]
    assert state["complete"] is complete
    assert state["aborted"] is aborted


def test_tracing_excludes_installed_plugin_namespace(monkeypatch):
    import importlib.util
    import sys
    from types import ModuleType
    from binassist_mcp import execution, execution_scope

    package = "BinAssistMCP.src.binassist_mcp"
    for name in ("BinAssistMCP", "BinAssistMCP.src", package):
        parent = ModuleType(name)
        parent.__path__ = []
        monkeypatch.setitem(sys.modules, name, parent)
    monkeypatch.setitem(sys.modules, package + ".execution", execution)
    spec = importlib.util.spec_from_file_location(package + ".execution_scope", execution_scope.__file__)
    installed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installed)
    frame = SimpleNamespace(f_code=execution.Execution.checkpoint.__code__,
                            f_globals={"__name__": package + ".execution"})
    assert not installed.ExecutionScope._user_frame(frame)
    frame.f_globals["__name__"] = "user_analysis_helpers"
    assert installed.ExecutionScope._user_frame(frame)
