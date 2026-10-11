"""Audit regressions using real native views and controlled synchronization."""

import asyncio
import builtins
import io
import os
import sys
import threading
import time
from types import ModuleType, SimpleNamespace

import pytest

os.environ.setdefault("BN_DISABLE_USER_PLUGINS", "1")
bn = pytest.importorskip("binaryninja")

from binassist_mcp.analysis_helpers import ScriptHelpers
from binassist_mcp.context import BinaryInfo, BinAssistMCPBinaryContextManager
from binassist_mcp.execution import Execution
from binassist_mcp.python_console import BinaryNinjaPythonConsole
from binassist_mcp.server import BinAssistMCPServer
from binassist_mcp.tools import BinAssistMCPTools


@pytest.fixture(autouse=True)
def isolated_startup(tmp_path, monkeypatch):
    (tmp_path / "startup.py").write_text("from binaryninja import *\n", encoding="utf-8")
    monkeypatch.setattr(bn, "user_directory", lambda: str(tmp_path))


@pytest.fixture
def view():
    return bn.BinaryView.new(b"A" * 32)


@pytest.fixture
def console(view):
    console = BinaryNinjaPythonConsole()
    assert console.execute(view, "1")["success"]
    yield console
    if console.busy:
        console._active.request_cancel()
        assert console._active.done.wait(4), "Regression left an interpreter running"
    console.close()


def test_nested_imported_helper_cancels_before_same_line_write(console, view, tmp_path):
    helper = ModuleType("audit_helper")
    exec(compile("import time\ndef outer(view):\n    inner(view)\n"
                 "def inner(view):\n    time.sleep(0.15); view.write(0, b'Z')\n",
                 str(tmp_path / "audit_helper.py"), "exec"), helper.__dict__)
    console._native_instance.interpreter.locals["helper"] = helper
    result = console.execute(view, "helper.outer(bv)", timeout_seconds=0.03)
    job = console.get_execution(result["execution_id"])
    assert job.done.wait(3)
    assert job.status == "timeout"
    assert view.read(0, 1) == b"A"


def test_imported_python_loop_observes_cancellation(console, view, tmp_path):
    helper = ModuleType("audit_loop")
    exec(compile("def outer():\n    inner()\ndef inner():\n    while True:\n        value = 1\n",
                 str(tmp_path / "audit_loop.py"), "exec"), helper.__dict__)
    console._native_instance.interpreter.locals["helper"] = helper
    result = console.execute(view, "helper.outer()", timeout_seconds=0.03)
    assert console.get_execution(result["execution_id"]).done.wait(3)
    assert console.execute(view, "2")["success"]


@pytest.mark.parametrize("start", ["threading.Thread(target=child).start()", "mcp.spawn(child)"])
def test_child_and_grandchild_drain_before_completion(console, view, start):
    entered, release = threading.Event(), threading.Event()
    console._native_instance.interpreter.locals.update(entered=entered, release=release)
    source = """import threading
def grandchild(view=bv, helper=mcp):
    entered.set()
    release.wait(3)
    view.write(0, b'Z')
    helper.emit({'child': 'done'})
def child():
    threading.Thread(target=grandchild).start()
""" + start
    job = console.start(view, source)
    try:
        assert entered.wait(2)
        assert not job.done.is_set() and console.busy
        assert console.execute(view, "2")["status"] == "busy"
        assert job.snapshot()["active_children"] >= 1
    finally:
        release.set()
    assert job.done.wait(3)
    result = job.snapshot()
    assert result["status"] == "ok" and result["active_children"] == 0
    assert result["results"] == [{"child": "done"}]
    assert view.read(0, 1) == b"Z"


def test_child_timeout_prevents_write_and_preserves_finally(console, view):
    result = console.execute(view, """import threading, time
cleaned = False
def child(view=bv):
    global cleaned
    try:
        time.sleep(0.15); view.write(0, b'Z')
    finally:
        cleaned = True
threading.Thread(target=child).start()
""", timeout_seconds=0.03)
    job = console.get_execution(result["execution_id"])
    assert job.done.wait(3)
    assert job.status == "timeout" and view.read(0, 1) == b"A"
    assert console.execute(view, "cleaned")["output"] == "True\n"


def test_child_failure_is_an_execution_error(console, view):
    result = console.execute(view, "def child():\n    raise ValueError('child failure')\nmcp.spawn(child)")
    assert result["status"] == "error"
    assert result["error"]["type"] == "ValueError"


def test_undo_group_drains_children_before_rollback(console, view):
    result = console.execute(view, """import time
def child(view=bv):
    time.sleep(0.05)
    view.write(0, b'Z')
with mcp.undo_group():
    mcp.spawn(child)
    raise ValueError('rollback children too')
""")
    assert result["status"] == "error"
    assert view.read(0, 1) == b"A"


def test_persistent_function_traceback_retains_bounded_source(console, view):
    import linecache
    defined = console.execute(view, "def fail():\n    raise ValueError('source-line-marker')")
    filename = f"<binassist:{defined['execution_id']}>"
    result = console.execute(view, "fail()")
    assert "raise ValueError('source-line-marker')" in result["error"]["traceback"]
    console.close()
    assert filename not in linecache.cache


def test_unmanaged_low_level_thread_start_is_rejected(console, view):
    result = console.execute(view, "import _thread\n_thread.start_new_thread(lambda: None, ())")
    assert result["status"] == "error" and "unmanaged" in result["error"]["message"]


def test_thread_pool_requires_scoped_shutdown_and_keeps_working(console, view):
    result = console.execute(view, "from concurrent.futures import ThreadPoolExecutor\n"
                             "pool = ThreadPoolExecutor(2)\npool.submit(lambda: 1)")
    assert result["status"] == "error" and "with block" in result["error"]["message"]
    result = console.execute(view, "with ThreadPoolExecutor(2) as pool:\n"
                             "    values = list(pool.map(lambda n: n * 2, range(4)))\nvalues")
    assert result["success"] and result["output"] == "[0, 2, 4, 6]\n"


def test_thread_pool_and_undo_group_nesting_is_explicit(console, view):
    result = console.execute(view, "from concurrent.futures import ThreadPoolExecutor\n"
                             "with ThreadPoolExecutor(1) as pool:\n"
                             "    with mcp.undo_group():\n        bv.write(0, b'Z')")
    assert result["status"] == "error" and "Nest ThreadPoolExecutor" in result["error"]["message"]
    assert view.read(0, 1) == b"A"
    result = console.execute(view, "with mcp.undo_group():\n"
                             "    with ThreadPoolExecutor(1) as pool:\n"
                             "        pool.submit(bv.write, 0, b'Z').result()\n"
                             "    raise ValueError('rollback')")
    assert result["status"] == "error" and view.read(0, 1) == b"A"


def test_stdio_is_serialized_and_queue_timeout_does_not_run_payload(console, view, monkeypatch):
    # Pytest replaces sys.stdout between fixture setup and the call phase.
    # Restore the native bridge installed by the warmup, as in the live host.
    monkeypatch.setattr(sys, "stdout", console._stdio_installed[1])
    other = BinaryNinjaPythonConsole()
    other_view = bn.BinaryView.new(b"B" * 16)
    assert other.execute(other_view, "1")["success"]
    bridge = sys.stdout
    entered, release = threading.Event(), threading.Event()
    console._native_instance.interpreter.locals.update(entered=entered, release=release, capture=io.StringIO())
    first = console.start(view, "import contextlib\nwith contextlib.redirect_stdout(capture):\n    entered.set()\n    release.wait(3)")
    try:
        assert entered.wait(2)
        queued = other.execute(other_view, "bv.write(0, b'Z')", timeout_seconds=0.03)
        assert queued["timed_out"]
        assert other.get_execution(queued["execution_id"]).done.wait(2)
        assert other_view.read(0, 1) == b"B"
        second = other.start(other_view, "print('second')")
        assert not second.done.wait(0.03)
    finally:
        release.set()
        assert first.done.wait(3)
    try:
        assert second.done.wait(3)
        assert second.snapshot()["output"] == "second\n"
        assert sys.stdout is bridge
    finally:
        other.close()


def test_duplicate_views_and_legacy_aliases_share_a_lease(view):
    manager = BinAssistMCPBinaryContextManager()
    try:
        assert manager.add_binary(view, "first") == "first"
        assert manager.add_binary(view, "duplicate") == "first"
        # Also protect aliases restored from older contexts or custom callers.
        manager._binaries["alias"] = BinaryInfo("alias", view)
        manager.execute_python("first", "import time")
        job = manager.start_python("first", "time.sleep(0.2)")
        assert manager.start_python("alias", "bv.write(0, b'Z')")["status"] == "busy"
        with pytest.raises(RuntimeError, match="busy"):
            with manager.binary_edit("alias"):
                pass
        assert not manager.remove_binary("alias")
        assert job.done.wait(3)
        assert view.read(0, 1) == b"A"
    finally:
        manager.clear()


def test_distinct_views_of_one_file_share_edit_reservations(view):
    mapped = bn.BinaryViewType["Mapped"].create(view)
    assert mapped is not None
    manager = BinAssistMCPBinaryContextManager()
    try:
        assert manager.add_binary(view, "raw") == "raw"
        assert manager.add_binary(mapped, "mapped") == "mapped"
        with manager.binary_edit("raw"):
            with pytest.raises(RuntimeError, match="busy"):
                with manager.binary_edit("mapped"):
                    pass
            assert manager.start_python("mapped", "1")["status"] == "busy"
            assert not manager.remove_binary("mapped")
    finally:
        manager.clear()


def function_view():
    view = bn.BinaryView.new(bytes.fromhex("55 48 89 e5 31 c0 5d c3") * 4)
    view.platform = bn.Platform["linux-x86_64"]
    view.create_user_function(0)
    view.update_analysis_and_wait()
    assert view.get_function_at(0) is not None
    return view


def test_query_that_generates_analysis_respects_python_lease():
    async def scenario():
        view = function_view()
        function = view.get_function_at(0)
        function.analysis_skipped = True
        view.update_analysis_and_wait()
        manager = BinAssistMCPBinaryContextManager()
        manager.add_binary(view, "sample")
        server = BinAssistMCPServer().create_mcp_server()
        ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=manager, session=object()))
        try:
            manager.execute_python("sample", "import time")
            job = manager.start_python("sample", "time.sleep(0.2)")
            with pytest.raises(Exception, match="busy"):
                await server._tool_manager.get_tool("get_code").run(
                    {"filename": "sample", "function_name_or_address": "0x0"}, context=ctx)
            assert function.analysis_skipped
            assert await asyncio.to_thread(job.done.wait, 3)
        finally:
            manager.clear()
    asyncio.run(scenario())


def test_repl_underscore_is_local_and_builtins_remain_unchanged(view, monkeypatch):
    sentinel = object()
    monkeypatch.setattr(builtins, "_", sentinel, raising=False)
    first, second = BinaryNinjaPythonConsole(), BinaryNinjaPythonConsole()
    try:
        result = first.execute(view, "for i in range(2):\n    i", mode="repl")
        assert result["output"] == "0\n1\n" and result["success"]
        assert first.execute(view, "_")["output"] == "1\n"
        first.close()
        assert second.execute(view, "_")["error"]["type"] == "NameError"
        assert builtins._ is sentinel
    finally:
        first.close()
        second.close()


def test_aborted_analysis_is_not_complete():
    view = function_view()
    manager = BinAssistMCPBinaryContextManager()
    manager.add_binary(view, "sample")
    try:
        view.abort_analysis()
        state = manager.get_analysis_progress("sample")
        assert state["idle"] and state["aborted"] and not state["analysis_complete"]
        helper = ScriptHelpers(Execution(30, 1024), view)
        with pytest.raises(RuntimeError, match="aborted"):
            helper.wait_for_analysis()
    finally:
        manager.clear()


def test_function_snapshot_has_stable_membership_across_executions():
    view = function_view()
    helper = ScriptHelpers(Execution(30, 1024), view)
    snapshot = helper.function_snapshot()
    original = [(f.platform.name, f.start) for f in helper.functions(snapshot=snapshot)]
    view.create_user_function(16)
    view.update_analysis_and_wait()
    next_helper = ScriptHelpers(Execution(30, 1024), view)
    assert [(f.platform.name, f.start) for f in next_helper.functions(snapshot=snapshot)] == original
    assert len(next_helper.function_snapshot()) > len(snapshot)
    with pytest.raises(ValueError, match="different"):
        list(ScriptHelpers(Execution(30, 1024), function_view()).functions(snapshot=snapshot))


@pytest.mark.parametrize("cancel_tool", ["py_cancel", "cancel_task"])
def test_task_and_execution_agree_about_cancellation(view, cancel_tool):
    async def scenario():
        manager = BinAssistMCPBinaryContextManager()
        manager.add_binary(view, "sample")
        server = BinAssistMCPServer().create_mcp_server()
        ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=manager, session=object()))

        async def call(name, args):
            return await server._tool_manager.get_tool(name).run(args, context=ctx)

        try:
            await call("py_exec", {"filename": "sample", "code": "import time"})
            task = await call("start_task", {"name": "cancel", "tool_name": "py_exec", "arguments":
                              {"filename": "sample", "code": "time.sleep(0.2)"}})
            args = ({"filename": "sample", "execution_id": task["execution_id"]} if cancel_tool == "py_cancel"
                    else {"task_id": task["task_id"]})
            future = manager.task_manager._running_futures[task["task_id"]]
            await call(cancel_tool, args)
            await future
            result = await call("get_task_status", {"task_id": task["task_id"]})
            assert result["status"] == result["execution_status"] == "cancelled"
        finally:
            await manager.task_manager.close()
            manager.clear()
    asyncio.run(scenario())


def test_blocking_query_does_not_block_transport_loop(monkeypatch):
    view = function_view()
    def slow_analysis(*args, **kwargs):
        time.sleep(0.2)
        return {"success": True}
    monkeypatch.setattr(BinAssistMCPTools, "get_code", slow_analysis)

    async def scenario():
        manager = BinAssistMCPBinaryContextManager()
        manager.add_binary(view, "sample")
        server = BinAssistMCPServer().create_mcp_server()
        ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=manager, session=object()))
        try:
            ticks = []
            start = time.monotonic()
            asyncio.get_running_loop().call_later(0.02, lambda: ticks.append(time.monotonic() - start))
            await server._tool_manager.get_tool("get_code").run(
                {"filename": "sample", "function_name_or_address": "0x0"}, context=ctx)
            assert ticks and ticks[0] < 0.15
        finally:
            manager.clear()
    asyncio.run(scenario())
