"""Integration regressions: requires a licensed headless Binary Ninja API."""

import asyncio
import os
import time
from types import SimpleNamespace

import pytest

os.environ.setdefault("BN_DISABLE_USER_PLUGINS", "1")
bn = pytest.importorskip("binaryninja")

from binassist_mcp.context import BinAssistMCPBinaryContextManager
from binassist_mcp.python_console import BinaryNinjaPythonConsole
from binassist_mcp.server import BinAssistMCPServer


@pytest.fixture(autouse=True)
def isolated_startup(tmp_path, monkeypatch):
    (tmp_path / "startup.py").write_text("from binaryninja import *\n", encoding="utf-8")
    monkeypatch.setattr(bn, "user_directory", lambda: str(tmp_path))


@pytest.fixture
def console():
    console = BinaryNinjaPythonConsole()
    yield console
    if console.busy:
        console._active.request_cancel()
        console._active.done.wait(2)
    console.close()


@pytest.fixture
def view():
    return bn.BinaryView.new(b"A" * 32)


def test_complete_script_and_persistent_functions(console, view):
    result = console.execute(view, "values=[]\nfor i in range(3):\n    values.append(i)\nvalues")
    assert result["success"] and result["stdout"] == "[0, 1, 2]\n"
    assert console.execute(view, "def value():\n    return values[-1]")["success"]
    assert console.execute(view, "value()")["stdout"] == "2\n"


def test_compile_and_runtime_errors_stop_later_mutation(console, view):
    invalid = console.execute(view, 'bv.write(0,b"Z")\nif (')
    assert invalid["error"]["type"] == "SyntaxError"
    assert view.read(0, 1) == b"A"
    failure = console.execute(view, 'raise RuntimeError("stop")\nbv.write(0,b"Z")')
    assert failure["error"]["type"] == "RuntimeError"
    assert view.read(0, 1) == b"A"


def test_output_saturation_and_stderr_do_not_determine_success(console, view):
    failure = console.execute(view, 'print("X"*1000000)\nraise ValueError("visible")', max_output_bytes=1024)
    assert not failure["success"] and failure["truncated"]
    assert failure["error"]["type"] == "ValueError"
    assert "visible" in failure["error"]["traceback"]
    success = console.execute(view, 'import sys\nsys.stderr.write("progress\\n")')
    assert success["success"] and success["stderr"] == "progress\n"


@pytest.mark.parametrize("source, status", [
    ("raise SystemExit(0)", "error"),
    ('input("value: ")', "input_required"),
    ('import builtins; builtins.input("value: ")', "input_required"),
    ('import sys; sys.stdin.readline()', "input_required"),
])
def test_exit_and_input_are_recoverable(console, view, source, status):
    result = console.execute(view, source, timeout_seconds=2)
    assert result["status"] == status and not result["still_running"]
    assert console.execute(view, "1+1")["stdout"] == "2\n"


def test_input_in_function_from_previous_call(console, view):
    assert console.execute(view, "def ask():\n    return input()")["success"]
    assert console.execute(view, "ask()")["status"] == "input_required"
    assert console.execute(view, "2")["success"]


def test_deadline_blocks_mutation_on_same_line(console, view):
    console.execute(view, "import time")
    start = time.monotonic()
    result = console.execute(view, 'time.sleep(0.3); bv.write(0,b"Z")', timeout_seconds=0.03)
    assert time.monotonic() - start < 0.2
    assert result["timed_out"] and result["still_running"]
    assert console.execute(view, "123")["status"] == "busy"
    assert not console.close()
    execution = console._active
    assert execution.done.wait(2)
    assert execution.snapshot()["status"] == "timeout"
    assert view.read(0, 1) == b"A"


def test_headless_address_and_result_helpers(console, view):
    result = console.execute(view, 'here=4\nmcp.emit({"value": 5})\nmcp.checkpoint(0.5,"half")')
    assert result["success"] and result["address"] == "0x4"
    assert result["results"] == [{"value": 5}]
    assert console.execute(view, "here")["stdout"] == "4\n"


def test_undo_group_reverts_error_and_cancellation(console, view):
    failure = console.execute(view, 'with mcp.undo_group():\n    bv.write(0,b"Z")\n    raise ValueError("rollback")')
    assert failure["status"] == "error" and view.read(0, 1) == b"A"
    console.execute(view, "import time")
    failure = console.execute(view, 'with mcp.undo_group():\n    bv.write(0,b"Z")\n    time.sleep(0.25)',
                              timeout_seconds=0.03)
    assert failure["timed_out"]
    assert console.get_execution(failure["execution_id"]).done.wait(2)
    assert view.read(0, 1) == b"A"


def test_cancelled_script_finally_releases_resources(console, view):
    console.execute(view, "import time\ncleaned=False")
    result = console.execute(view, 'try:\n    time.sleep(0.2)\nfinally:\n    cleaned=True', timeout_seconds=0.03)
    assert console.get_execution(result["execution_id"]).done.wait(2)
    assert console.execute(view, "cleaned")["stdout"] == "True\n"


def test_deadline_includes_startup(console, view, tmp_path):
    (tmp_path / "startup.py").write_text("import time\ntime.sleep(0.2)\nfrom binaryninja import *\n")
    result = console.execute(view, 'bv.write(0,b"Z")', timeout_seconds=0.02)
    assert result["timed_out"] and result["still_running"]
    assert console.get_execution(result["execution_id"]).done.wait(2)
    assert view.read(0, 1) == b"A"


def test_release_restores_process_stdio(view):
    import sys
    before = (sys.stdin, sys.stdout, sys.stderr)
    console = BinaryNinjaPythonConsole()
    assert console.execute(view, "1")["success"]
    console.close()
    assert (sys.stdin, sys.stdout, sys.stderr) == before


def test_per_binary_session_isolation_and_eviction_lease():
    manager = BinAssistMCPBinaryContextManager(max_binaries=2)
    a = bn.BinaryView.new(b"A" * 16)
    b = bn.BinaryView.new(b"B" * 16)
    manager.add_binary(a, "a")
    manager.add_binary(b, "b")
    try:
        assert manager.execute_python("a", "saved=bv")["success"]
        result = manager.execute_python("b", "saved")
        assert result["error"]["type"] == "NameError"
        result = manager.execute_python("a", "saved", session="other")
        assert result["error"]["type"] == "NameError"
        job = manager.start_python("a", "import time; time.sleep(0.2)")
        assert not manager.remove_binary("a")
        assert manager.start_python("a", "1", session="other")["status"] == "busy"
        manager.add_binary(bn.BinaryView.new(b"C"), "c")
        assert manager.list_binaries() == ["a", "c"]
        assert job.done.wait(2)
        assert manager.reset_python("a")["success"]
        assert manager.execute_python("a", "saved")["error"]["type"] == "NameError"
    finally:
        manager.clear()


def test_idle_sessions_expire_and_release_namespaces(view):
    manager = BinAssistMCPBinaryContextManager()
    manager.add_binary(view, "audit")
    try:
        first = manager.execute_python("audit", "remembered=42")
        manager._python_last_used[("audit", "default")] -= 1000
        second = manager.execute_python("audit", "remembered")
        assert second["error"]["type"] == "NameError"
        assert second["namespace_created"]
        assert first["namespace_id"] != second["namespace_id"]
    finally:
        manager.clear()


def test_registered_tools_do_not_block_loop_and_dispatch_real_tasks():
    async def scenario():
        manager = BinAssistMCPBinaryContextManager()
        manager.add_binary(bn.BinaryView.new(b"A" * 16), "audit")
        server = BinAssistMCPServer().create_mcp_server()
        ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=manager, session=object()))

        async def call(name, args):
            return await server._tool_manager.get_tool(name).run(args, context=ctx)

        try:
            await call("py_exec", {"filename": "audit", "code": "import time"})
            ticks = []
            start = time.monotonic()
            asyncio.get_running_loop().call_later(0.02, lambda: ticks.append(time.monotonic() - start))
            await call("py_exec", {"filename": "audit", "code": "time.sleep(0.2)"})
            assert ticks and ticks[0] < 0.15
            started = await call("start_task", {"name": "actual", "tool_name": "py_exec",
                                 "arguments": {"filename": "audit", "code": "time.sleep(0.3); bv.write(0,b'Z')"}})
            with pytest.raises(Exception, match="busy"):
                await call("rename_symbol", {"filename": "audit", "address_or_name": "0x0", "new_name": "blocked"})
            await call("cancel_task", {"task_id": started["task_id"]})
            for _ in range(100):
                status = await call("get_task_status", {"task_id": started["task_id"]})
                if not status["still_running"]:
                    break
                await asyncio.sleep(0.01)
            assert status["status"] == "cancelled"
            assert manager.get_binary("audit").read(0, 1) == b"A"
            real = await call("start_task", {"name": "list", "tool_name": "get_binary_info",
                              "arguments": {"filename": "audit"}})
            future = manager.task_manager._running_futures[real["task_id"]]
            await future
            assert manager.task_manager.get_task_status(real["task_id"])["status"] == "completed"
            # Capacity must be checked before a Python task can modify its view.
            manager.task_manager._max_tasks = 0
            with pytest.raises(Exception, match="capacity"):
                await call("start_task", {"name": "rejected", "tool_name": "py_exec",
                           "arguments": {"filename": "audit", "code": 'bv.write(0,b"Q")'}})
            assert manager.get_binary("audit").read(0, 1) == b"A"
        finally:
            await manager.task_manager.close()
            manager.clear()

    asyncio.run(scenario())


def test_rpc_cancellation_reaches_running_script(view):
    async def scenario():
        manager = BinAssistMCPBinaryContextManager()
        manager.add_binary(view, "audit")
        server = BinAssistMCPServer().create_mcp_server()
        ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=manager, session=object()))
        tool = server._tool_manager.get_tool("py_exec")
        try:
            future = asyncio.create_task(tool.run({"filename": "audit", "code":
                         'import time; time.sleep(0.25); bv.write(0,b"Z")'}, context=ctx))
            while not manager._python_consoles:
                await asyncio.sleep(0.005)
            await asyncio.sleep(0.04)
            execution = next(iter(manager._python_consoles.values()))._active
            future.cancel()
            with pytest.raises(asyncio.CancelledError):
                await future
            assert await asyncio.to_thread(execution.done.wait, 2)
            assert execution.snapshot()["status"] == "cancelled"
            assert view.read(0, 1) == b"A"
        finally:
            manager.clear()

    asyncio.run(scenario())


def test_status_pages_are_scoped_to_the_client(view):
    async def scenario():
        manager = BinAssistMCPBinaryContextManager()
        manager.add_binary(view, "audit")
        server = BinAssistMCPServer().create_mcp_server()
        ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=manager, session=object()))
        other = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=manager, session=object()))
        try:
            result = await server._tool_manager.get_tool("py_exec").run(
                {"filename": "audit", "code": 'print("abcdefgh")\nmcp.emit({"found": 1})'}, context=ctx)
            args = {"filename": "audit", "execution_id": result["execution_id"], "output_limit": 4}
            status_tool = server._tool_manager.get_tool("py_status")
            first = await status_tool.run(args, context=ctx)
            second = await status_tool.run({**args, "output_offset": first["next_offset"]}, context=ctx)
            assert first["output"] == "abcd" and second["output"] == "efgh"
            assert first["results"] == [{"found": 1}]
            with pytest.raises(Exception, match="session not found"):
                await status_tool.run(args, context=other)
        finally:
            manager.clear()

    asyncio.run(scenario())
