# BinAssistMCP

> Comprehensive Model Context Protocol (MCP) server for Binary Ninja with AI-powered reverse engineering capabilities

## Summary

BinAssistMCP is a powerful bridge between Binary Ninja and Large Language Models (LLMs) like Claude, providing comprehensive reverse engineering tools through the Model Context Protocol (MCP). It enables AI-assisted binary analysis by exposing Binary Ninja's advanced capabilities through Server-Sent Events (SSE) and Streamable HTTP transports.

### Key Features

- **MCP 2025-11-25 Compliant**: Full support for tool annotations, resources, and prompts
- **Dual Transport Support**: SSE (Server-Sent Events) and Streamable HTTP transports
- **48 Consolidated Tools**: Streamlined Binary Ninja API wrapper with unified tool design
- **Managed Python Scripts**: Complete scripts on the native interpreter, isolated sessions, bounded output, progress and cooperative cancellation, including headless mode
- **8 MCP Resources**: Browsable, cacheable binary metadata
- **7 Guided Prompts**: Pre-built workflows for common reverse engineering tasks
- **Multi-Binary Sessions**: Concurrent analysis of multiple binaries with intelligent context management
- **Analysis Caching**: LRU cache with binary-scoped invalidation for improved performance
- **Async Task Support**: Non-blocking execution for long-running operations
- **Thread-Safe**: RLock-based synchronization for concurrent access
- **Auto-Integration**: Seamless Binary Ninja plugin with automatic startup capabilities

### Use Cases

- **AI-Assisted Reverse Engineering**: Leverage LLMs for intelligent code analysis and documentation
- **Protocol Analysis**: Trace network data flows and reconstruct protocol structures
- **Vulnerability Research**: Systematic security audits with guided workflows
- **Automated Binary Analysis**: Script complex analysis workflows with natural language
- **Code Understanding**: Generate comprehensive documentation and explanations

---

## Architecture

```
src/binassist_mcp/
├── server.py        # FastMCP server - SSE/Streamable HTTP transport, tool registration
├── tools.py         # Binary Ninja API wrapper used by MCP tools
├── python_console.py # Native Binary Ninja Python Console bridge
├── execution.py     # Bounded output and execution lifecycle records
├── execution_scope.py # Cooperative tracing and managed child-thread lifetimes
├── analysis_helpers.py # Script batching, IL and undo helpers
├── function_context.py # UI-selected function, overlap and architecture resolution
├── analysis_queries.py # Bounded cached IL, CFG and summary queries
├── plugin.py        # Binary Ninja plugin integration
├── context.py       # Thread-safe multi-binary session management
├── config.py        # Pydantic configuration with Binary Ninja settings
├── prompts.py       # 7 guided workflow prompts
├── resources.py     # 8 MCP resource definitions
├── cache.py         # LRU analysis cache with invalidation
├── tasks.py         # Async task manager for long-running operations
├── logging.py       # Binary Ninja logging integration
└── utils.py         # Utility functions

__init__.py          # Plugin entry point (root level)
```

---

## Tools (48 Total)

BinAssistMCP provides 48 tools organized into functional categories. Tools include MCP annotations (`readOnlyHint`, `idempotentHint`) to help clients make informed decisions.

### Binary Management
| Tool | Description |
|------|-------------|
| `list_binaries` | List all loaded binary files |
| `get_binary_info` | Check analysis status and metadata |
| `open_binary` | Open a binary or BNDB in the UI or headlessly |
| `update_analysis_and_wait` | Force analysis update and wait for completion |
| `export_program` | Export the patched binary or Binary Ninja database to disk |

### Python Console
| Tool | Description |
|------|-------------|
| `py_exec` | Execute a complete script with `bv`, `here`, persistent variables, progress and optional background execution |
| `py_status` | Read actual execution state and paginated output/results |
| `py_cancel` | Request cooperative cancellation; inspect `still_running` for completion |
| `py_reset` | Release an idle session and clear its variables and history |

### Code Analysis (Consolidated)
| Tool | Description |
|------|-------------|
| `get_code` | Cached IL instruction pages by default; explicit generation and full rendering are available |
| `get_function_low_level_il` | Read a bounded cached LLIL page with the same generation policy as `get_code` |
| `analyze_function` | Bounded function summary with explicit scanned-block coverage |
| `get_basic_blocks` | Paged CFG blocks with separately paginated predecessor/successor edges |
| `get_function_stack_layout` | Get stack frame layout with variable offsets |

### Cross-References (Consolidated)
| Tool | Description |
|------|-------------|
| `xrefs` | **Unified cross-references** - actions: `refs_to`, `refs_from`, `call_graph` |

### Comments (Consolidated)
| Tool | Description |
|------|-------------|
| `comments` | **Unified comment management** - actions: `get`, `set`, `list`, `remove`, `set_function` |

### Variables (Consolidated)
| Tool | Description |
|------|-------------|
| `variables` | **Unified variable management** - actions: `list`, `create`, `rename`, `set_type`; `rename` supports local/global via `scope` |

### Types (Consolidated)
| Tool | Description |
|------|-------------|
| `types` | **Unified type management** - actions: `create`, `create_enum`, `create_typedef`, `create_class`, `add_member`, `get_info`, `list` |
| `get_classes` | List all classes and structures |

### Function Discovery
| Tool | Description |
|------|-------------|
| `get_functions` | List all functions with metadata (paginated) |
| `search_functions_by_name` | Find functions by name pattern |
| `get_functions_advanced` | Advanced filtering by size, complexity, parameters |
| `search_functions_advanced` | Multi-target search (name, comments, calls, variables) |
| `get_function_statistics` | Comprehensive statistics for all functions |

### Symbol Management
| Tool | Description |
|------|-------------|
| `rename_symbol` | Rename functions and data variables |
| `batch_rename` | Rename multiple symbols in one operation |
| `get_namespaces` | List namespaces and symbol organization |

### Binary Information
| Tool | Description |
|------|-------------|
| `get_imports` | Import table grouped by module |
| `get_exports` | Export table with symbol information |
| `get_strings` | String extraction with filtering |
| `search_strings` | Search strings by pattern |
| `get_segments` | Memory segment layout |
| `get_sections` | Binary section information |
| `get_entry_points` | List all binary entry points |

### Data Analysis
| Tool | Description |
|------|-------------|
| `create_data_var` | Define data variables at addresses |
| `get_data_vars` | List all defined data variables |
| `get_data_at` | Read and analyze raw data |
| `search_bytes` | Search for byte patterns in binary |

### Patching
| Tool | Description |
|------|-------------|
| `patch_bytes` | Patch raw bytes in the binary at an address |
| `assemble_code` | Assemble instruction text at an address and optionally patch it |

### Navigation & Bookmarks
| Tool | Description |
|------|-------------|
| `get_current_address` | Get current cursor position with context |
| `get_current_function` | Identify function at current address |
| `bookmarks` | **Unified bookmark management** - actions: `list`, `set`, `remove` |

### Task Management
| Tool | Description |
|------|-------------|
| `start_task` | Start an async background task |
| `get_task_status` | Check status of async operations |
| `list_tasks` | List all pending/running tasks |
| `cancel_task` | Cancel a running task |

---

## MCP Resources (8 Total)

Resources provide browsable, cacheable data that clients can access without tool calls.

| URI Pattern | Description |
|-------------|-------------|
| `binassist://{filename}/triage_summary` | Complete binary overview |
| `binassist://{filename}/functions` | All functions with metadata |
| `binassist://{filename}/imports` | Import table |
| `binassist://{filename}/exports` | Export table |
| `binassist://{filename}/strings` | String table |
| `binja://{filename}/info` | Binary metadata (arch, platform, entry point) |
| `binja://{filename}/segments` | Memory segments with permissions |
| `binja://{filename}/sections` | Binary sections |

---

## MCP Prompts (7 Total)

Pre-built prompts guide LLMs through structured analysis workflows.

| Prompt | Arguments | Description |
|--------|-----------|-------------|
| `analyze_function` | `function_name`, `filename` | Comprehensive function analysis workflow |
| `identify_vulnerability` | `function_name`, `filename` | Security audit checklist (memory safety, input validation, crypto) |
| `document_function` | `function_name`, `filename` | Generate Doxygen-style documentation |
| `trace_data_flow` | `address`, `filename` | Track data dependencies and taint propagation |
| `compare_functions` | `func1`, `func2`, `filename` | Diff two functions for similarity analysis |
| `reverse_engineer_struct` | `address`, `filename` | Recover structure definitions from usage patterns |
| `trace_network_data` | `filename` | Trace POSIX/Winsock send/recv for protocol analysis |

### Example: Network Protocol Analysis

The `trace_network_data` prompt guides analysis of network communication:

1. **Identify Network Functions**: Finds POSIX (`send`/`recv`/`sendto`/`recvfrom`) and Winsock (`WSASend`/`WSARecv`) calls
2. **Trace Call Stacks**: Maps application handlers down to network I/O
3. **Analyze Buffers**: Identifies protocol structures (headers, length fields, TLV encoding)
4. **Reconstruct Protocols**: Generates C struct definitions for message formats
5. **Security Assessment**: Checks for buffer overflows, integer issues, information disclosure

---

## Installation

### Prerequisites

- **Binary Ninja**: Version 4000 or higher
- **Python**: 3.10+ (required by the MCP dependency; typically bundled with Binary Ninja)
- **Platform**: Windows, macOS, or Linux

NOTE: Windows users should start with: [BinAssistMCP on Windows](binassistmcp-on-windows.md)

### Option 1: Binary Ninja Plugin Manager (Recommended)

1. Open Binary Ninja
2. Navigate to **Tools** → **Manage Plugins**
3. Search for "BinAssistMCP"
4. Click **Install**
5. Restart Binary Ninja

### Option 2: Manual Installation

```bash
# Clone the repository
git clone https://github.com/jtang613/BinAssistMCP.git
cd BinAssistMCP

# Install dependencies
pip install -r requirements.txt
```

Copy to your Binary Ninja plugins directory:

| Platform | Path |
|----------|------|
| Windows | `%APPDATA%\Binary Ninja\plugins\` |
| macOS | `~/Library/Application Support/Binary Ninja/plugins/` |
| Linux | `~/.binaryninja/plugins/` |

---

## Configuration

### Binary Ninja Settings

Open **Edit** → **Preferences** → **binassistmcp**:

| Setting | Default | Description |
|---------|---------|-------------|
| `server.host` | `localhost` | Server bind address |
| `server.port` | `9090` | Server port |
| `server.transport` | `streamablehttp` | Transport: `streamablehttp` or `sse` |
| `binary.max_binaries` | `10` | Maximum concurrent binaries |
| `plugin.auto_startup` | `true` | Auto-start server on file load |

### Environment Variables

```bash
export BINASSISTMCP_SERVER__HOST=localhost
export BINASSISTMCP_SERVER__PORT=9090
export BINASSISTMCP_SERVER__TRANSPORT=streamablehttp
export BINASSISTMCP_BINARY__MAX_BINARIES=10
```

---

## Usage

### Starting the Server

**Via Binary Ninja Menu:**
1. **Tools** → **BinAssistMCP** → **Start Server**
2. Check log panel for: `BinAssistMCP server started on http://localhost:9090`

**Auto-Startup:**
Server starts automatically when Binary Ninja loads a file (configurable).

### Connecting MCP Clients

**Streamable HTTP (Default):**
```
http://localhost:9090/mcp
```

**Server-Sent Events:**
```
http://localhost:9090/sse
```

### Function Context and Bounded Queries

`get_current_function` and `get_current_address` read a coherent selection from the Binary Ninja UI on its main thread. The selected function must belong to the requested BinaryView. If Binary Ninja is not in the foreground, a unique visible selection for that view is used; conflicting panes/windows produce `context_unavailable`. Headless mode does not fabricate a current UI cursor.

Function queries accept an exact name, an entry address, or an interior address. A unique exact entry takes precedence for an explicit address; otherwise the selected UI function resolves overlapping owners. Without a reliable selection, overlapping functions return `ambiguous_function` with candidates rather than silently selecting the first result. Use `function_start`, `architecture`, and `platform` to select explicitly. Responses include the actual `function_start`, `architecture`, `platform`, `requested_address`, and `context_source`. Current-address disassembly uses the selected function's ISA, so a Thumb function inside an ARM-default view is decoded as Thumb. Function bounds are not treated as a contiguous range or computed by adding total bytes to the entry address.

`get_code` defaults to `generate=false` and returns native IL instruction fragments, labelled by `representation`. `decompile` prefers cached HLIL, then cached MLIL, without silently substituting assembly. Missing IL returns `il_unavailable`; a generation request for a skipped function returns `analysis_skipped`. `generate=true` permits on-demand generation. Clearing a function's skip flag additionally requires `force_analysis=true`. The LLIL tool and legacy Python code-retrieval aliases follow the same policy. No query silently clears the skip flag.

Code pages use `offset`, `limit` (default 100 instructions), and `max_output_bytes` (default 16 KiB). Reuse returned function selectors and `snapshot_id` for subsequent IL pages; changed IL returns `stale_page`. Inspect `has_more`, `next_offset`, `complete`, and `truncated`. Fragments are not a complete structured function listing. `full_render=true` explicitly requests native full-function formatting, which can be expensive even before pagination; its offsets and limits count characters instead of instructions.

```json
{
  "filename": "sample.exe",
  "function_name_or_address": "0x401020",
  "function_start": "0x401000",
  "architecture": "x86_64",
  "format": "hlil",
  "offset": 0,
  "limit": 50
}
```

`get_basic_blocks` returns an object containing `blocks`, `total_blocks`, `offset`, `next_offset`, `has_more`, `edges_complete`, and `complete`; it no longer returns an unbounded bare list. Defaults are 50 blocks, 16 edges per direction per block, and 32 KiB. Use `block_address` to inspect one block, then advance `edge_offset` using its `predecessors_page` or `successors_page`. A page that ends the block list may still have incomplete edge lists. Keep function selectors fixed and restart pagination after reanalysis, which can change block order.

`analyze_function` scans at most 500 blocks by default. `block_scan` reports exactly which range its counts describe, with a continuation offset. Full instruction counts and the single-component cyclomatic estimate are returned only when all blocks were scanned. Instruction counts use the native instruction count, not byte length. Call-site counts are not labelled call depth, and backward address edges are not labelled loops.

### Python Console Execution

Call `py_exec` with a name returned by `list_binaries`:

```json
{
  "filename": "sample.exe",
  "code": "len(bv.functions)"
}
```

The default `mode="script"` compiles the complete source before running it once. Compound statements need no REPL separator lines. Syntax errors execute nothing, and an uncaught runtime error stops subsequent statements. The final expression is displayed with a bounded representation. `mode="repl"` accepts a single complete interactive statement. Both modes keep the last displayed value in the session-local `_`, without changing `builtins._`. Both modes catch `SystemExit`, and unattended input returns `input_required` instead of leaving the interpreter waiting for input.

Variables and imports persist within one client connection, binary and named `session` (default `"default"`). Connections receive independent UUIDs; a new connection or different binary has a separate namespace. Imported modules still share the host Python process and are not sandboxed. `startup.py` still runs when an interpreter is first created. The optional `address`, `function_start` and `architecture` select the current context; ambiguous functions require explicit selection. `py_reset` releases an idle namespace. It refuses to replace a still-running interpreter. New submissions reclaim sessions idle for more than 15 minutes, and the oldest idle session can be evicted when the 32-session capacity is reached. `namespace_id` identifies each incarnation; `namespace_created=true` signals an empty/new namespace, including after eviction. Active sessions are never evicted.

`timeout_seconds` is a cooperative deadline, default 30 seconds and maximum 600, including initialization and queue time. Python executions serialize across all MCP sessions because standard streams are process-global; waiting executions report `queued`. A blocked native operation may outlive its deadline. The result then has `status="cancel_requested"`, `timed_out=true` and `still_running=true`. The underlying database stays reserved until the interpreter and its enrolled child threads finish. Duplicate BinaryView wrappers are deduplicated, and views sharing a native file share the reservation. Mutating tools and analysis-generating queries such as `get_code` reject conflicts. GUI edits are outside this reservation.

Poll `py_status` using its `execution_id`; only `still_running=false` confirms completion. Line/call checks cover scripts and imported user Python modules, including nested calls, while allowing `finally` cleanup after cancellation. Standard-library and Binary Ninja bookkeeping are excluded from line tracing. A script that deliberately catches cancellation, disables tracing, blocks indefinitely in native code, or exits the host process cannot be forcibly contained in this in-process interpreter. Blocking MCP tools run off the transport event loop so status and cancellation remain responsive.

Set `background=true` to return an execution ID immediately. `py_status` accepts `output_offset`/`output_limit` and `result_offset`/`result_limit`; continue with `next_offset` and `next_result_offset`. Response pages default to 16 KiB. Output cursors count characters, while limits count UTF-8 bytes (minimum four bytes so any Unicode code point can fit). `output_complete` only means the current retained page is exhausted; output can grow until execution finishes. Ordinary output retains 64 KiB by default (`max_output_bytes`, 1 KiB to 1 MB), plus a separate 16 KiB diagnostic budget. Error status and structured traceback do not depend on captured stderr. Terminal output, results and progress are immutable. Each session retains eight executions and their source for traceback display, and a context permits 32 sessions. Reset unused sessions to release retained native objects.

`start_task` dispatches registered tools with an `arguments` object. Python tasks report an `execution_id` for output pagination. Task state `cancel_requested` is distinct from `cancelled`; a running synchronous tool is not reported cancelled until it returns. Both `py_cancel` and `cancel_task` produce a cancelled task when the Python execution finishes cancelled. Timeouts, input requests and script errors produce failed tasks with the specific execution status preserved. For example:

```json
{
  "name": "Inspect a function batch",
  "tool_name": "py_exec",
  "arguments": {
    "filename": "sample.exe",
    "code": "for f in mcp.functions(offset=0, limit=50):\n    mcp.emit(mcp.function_status(f))",
    "timeout_seconds": 60
  }
}
```

Scripts can use the injected `mcp` helper for bounded analysis:

```python
for index, function in enumerate(mcp.functions(offset=0, limit=50)):
    mcp.checkpoint(index / 50, function.name)
    status = mcp.function_status(function)
    il = mcp.get_il(function, level="hlil", generate=False)
    status["hlil_available"] = il is not None
    mcp.emit(status)
```

`mcp.emit` accepts JSON values, limited to 256 records and 64 KiB per execution. Split larger jobs into batches and paginate results. `mcp.get_il` uses already available IL by default; `generate=True` explicitly allows potentially expensive analysis. `mcp.walk_il(instruction, max_nodes=10000)` iterates nested expressions with cycle and node-budget checks. `mcp.write(text)` captures explicit child-thread output; ordinary child-thread `print` is not automatically associated with the parent execution.

`mcp.functions()` indexes only the requested batch and reuses one native function list within an execution. For paging across executions, create a compact membership snapshot once and keep it in the namespace:

```python
# First py_exec call. The default limit is 250,000 functions; maximum 1,000,000.
batch = mcp.function_snapshot()
len(batch)
```

```python
# Later py_exec calls in the same session: advance offset for each batch.
for function in mcp.functions(offset=100, limit=50, snapshot=batch):
    mcp.emit(mcp.function_status(function))
```

Snapshots retain the source view and compact platform/address locators, not Function or IL objects. They resolve fresh objects for each page. Newly discovered functions do not shift existing pages; a removed function produces a stale-snapshot error. Create a new snapshot to include new functions, and use `del batch` when finished.

Ordinary `threading.Thread.start()` calls made by an execution or its enrolled children are automatically enrolled, including daemon threads. `mcp.spawn(target, *args, **kwargs)` offers an explicit equivalent. An execution can start at most 64 threads, reports `active_children`, and drains children and grandchildren before becoming terminal. Child errors fail the execution and request cancellation of remaining work. Use a fresh `ThreadPoolExecutor` inside a `with` block; unscoped pools and submitting to pre-existing external workers are rejected. Low-level `_thread` starts are rejected. Native-created threads, external callback schedulers and subprocesses are not enrolled; keep their lifetimes within the script explicitly. Prefer `mcp.write()` to process-global output redirection in concurrent child code.

```python
def inspect_bytes(address, view=bv, helper=mcp):
    helper.emit({"address": hex(address), "bytes": view.read(address, 16).hex()})

mcp.spawn(inspect_bytes, here)
# Completion is reported only after inspect_bytes returns.
```

Script completion and analysis completion are separate. Inspect `analysis_at_start`, `analysis`, or `mcp.analysis_status()`. The fields distinguish `idle` from `aborted`; `complete=true` confirms an idle, non-aborted queue and carries `completeness="queue_state_only"`. It does not imply that every function has usable IL: inspect `mcp.function_status()` and IL availability too. `mcp.wait_for_analysis()` rejects aborted analysis and checks completion after waiting. This native wait remains cooperative and may outlive a timeout. Retrieve fresh function/IL objects after reanalysis. `with mcp.undo_group():` groups supported database changes, drains enrolled children before committing or rolling back, and reverts the group on failure or cancellation. Open undo groups on the interpreter thread; nest any `ThreadPoolExecutor` inside the undo group so its workers close before the group exits. Avoid concurrent UI edits during the group. It cannot undo external file/network effects or unsupported native changes.

> **Security:** `py_exec` runs trusted Python with the permissions of the Binary Ninja process. It can modify the analysis, access local files and the network, and invoke any installed Python package. Do not expose the MCP endpoint to untrusted clients.

### Tests

Create an isolated environment with `uv venv`, install `requirements.txt` and `pytest` using `uv pip install`, then run the environment's Python with `-m pytest`. Native integration tests require a licensed Binary Ninja Python API on `PYTHONPATH`; they skip when that API is unavailable. Tests use temporary in-memory BinaryViews and a temporary `startup.py`. The pytest configuration avoids importing the repository's plugin entry point and starting its server during collection.

### Claude Desktop Configuration

Add to your Claude Desktop MCP configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "binassist": {
      "url": "http://localhost:9090/mcp"
    }
  }
}
```

---

## Integration Examples

### Basic Function Analysis
```
User: "Analyze the main function and explain what it does"

Claude uses:
1. get_functions() - find main
2. get_code(format='decompile') - get readable code
3. xrefs(action='refs_from') - find called functions
4. analyze_function() - get complexity metrics
```

### Vulnerability Research
```
User: "Find buffer overflow vulnerabilities in input handling functions"

Claude uses:
1. search_functions_advanced(search_in='calls') - find memcpy/strcpy callers
2. get_code(format='decompile') - examine implementations
3. variables(action='list') - check buffer sizes
4. comments(action='set') - document findings
```

### Protocol Reverse Engineering
```
User: "Analyze the network protocol used by this binary"

Claude uses the trace_network_data prompt:
1. Identifies send/recv call sites
2. Traces data flow from handlers to network I/O
3. Reconstructs message structures
4. Checks for network vulnerabilities
```

---

## Troubleshooting

### Server Issues

| Problem | Solution |
|---------|----------|
| Server won't start | Check port 9090 availability, verify dependencies |
| Connection refused | Ensure server is running, check firewall settings |
| Tools return errors | Wait for analysis completion, verify binary is loaded |

### Performance

- **Slow decompilation**: Results are cached; second request is faster
- **Memory usage**: Reduce `max_binaries` setting
- **Long operations**: Check task status with `get_task_status`

### Logs

Check Binary Ninja's Log panel for detailed error messages.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Follow existing code patterns (Pydantic models, type hints, docstrings)
4. Test with multiple binary types
5. Submit a pull request

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
