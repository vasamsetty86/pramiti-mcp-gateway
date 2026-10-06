"""Tests for the passive relay (unit + real downstream) and posture report."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from pramiti_mcp_gateway import signing
from pramiti_mcp_gateway.posture import summarize
from pramiti_mcp_gateway.proxy import PassiveRelay
from pramiti_mcp_gateway.records import RecordStore, read_records

FIXTURES = Path(__file__).resolve().parent / "fixtures"


# --- unit: relay with a stubbed downstream ---------------------------------

class _Tool:
    def __init__(self, name, description="", inputSchema=None):
        self.name = name
        self.description = description
        self.inputSchema = inputSchema


class _Listed:
    def __init__(self, tools):
        self.tools = tools


class _Result:
    def __init__(self, content=None, isError=False):
        self.content = content or []
        self.isError = isError


class _FakeDownstream:
    def __init__(self, tools, fail=False):
        self._tools = tools
        self._fail = fail
        self.calls = []

    async def list_tools(self):
        return _Listed(self._tools)

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if self._fail:
            raise RuntimeError("downstream boom")
        return _Result(content=[{"type": "text", "text": "ok"}])


@pytest.mark.asyncio
async def _relay_records_a_forwarded_call(tmp_path):
    pass  # placeholder to satisfy tooling if asyncio plugin absent


def _run(coro):
    import asyncio
    return asyncio.run(coro)


def test_relay_forwards_and_records(tmp_path):
    tools = [
        _Tool("transfer_funds", "Wire funds. Irreversible.", {"properties": {"amt": {}}}),
        _Tool("list_items", "List available items."),
    ]
    down = _FakeDownstream(tools)
    store = RecordStore(str(tmp_path / "r.jsonl"), signer=None)
    relay = PassiveRelay(down, "payments", store)

    async def go():
        await relay.prime()
        await relay.handle_call("transfer_funds", {"amt": 100})
        await relay.handle_call("list_items", {})

    _run(go())

    # Both calls were forwarded downstream...
    assert down.calls == [("transfer_funds", {"amt": 100}), ("list_items", {})]
    # ...and both were recorded with the right severity.
    recs = read_records(str(tmp_path / "r.jsonl"))
    assert len(recs) == 2
    by_tool = {r["tool"]: r for r in recs}
    assert by_tool["transfer_funds"]["severity"] in ("high", "critical")
    assert by_tool["transfer_funds"]["access"] == "write"
    assert by_tool["list_items"]["severity"] == "info"
    assert all(r["outcome"] == "forwarded" for r in recs)


def test_relay_records_error_then_reraises(tmp_path):
    down = _FakeDownstream([_Tool("delete_it", "Deletes it.")], fail=True)
    store = RecordStore(str(tmp_path / "r.jsonl"), signer=None)
    relay = PassiveRelay(down, "s", store)

    async def go():
        await relay.prime()
        with pytest.raises(RuntimeError, match="boom"):
            await relay.handle_call("delete_it", {})

    _run(go())
    recs = read_records(str(tmp_path / "r.jsonl"))
    assert len(recs) == 1
    assert recs[0]["outcome"] == "error"


# --- unit: the agent-facing reply is the downstream result UNCHANGED --------
# A-RD-012: returning only result.content let the SDK re-wrap a downstream
# ERROR as a non-error reply (and dropped structuredContent). The relay's
# transparency claim is "returns the real result unchanged" — pin it.

def test_faithful_result_preserves_downstream_error_flag():
    pytest.importorskip("mcp")
    from mcp import types
    from pramiti_mcp_gateway.proxy import _faithful_result

    downstream = _Result(
        content=[types.TextContent(type="text", text="tool exploded")],
        isError=True,
    )
    reply = _faithful_result(downstream)
    assert isinstance(reply, types.CallToolResult)
    assert reply.isError is True, "downstream error re-presented as success"
    assert reply.content[0].text == "tool exploded"


def test_faithful_result_preserves_structured_content():
    pytest.importorskip("mcp")
    from mcp import types
    from pramiti_mcp_gateway.proxy import _faithful_result

    downstream = _Result(content=[types.TextContent(type="text", text="ok")])
    downstream.structuredContent = {"rows": [1, 2, 3]}
    reply = _faithful_result(downstream)
    assert reply.isError is False
    assert reply.structuredContent == {"rows": [1, 2, 3]}


def test_faithful_result_passes_real_calltoolresult_through_unchanged():
    pytest.importorskip("mcp")
    from mcp import types
    from pramiti_mcp_gateway.proxy import _faithful_result

    real = types.CallToolResult(
        content=[types.TextContent(type="text", text="boom")],
        structuredContent={"code": 42},
        isError=True,
    )
    assert _faithful_result(real) is real


# --- integration: relay against a REAL downstream MCP server ---------------

def test_relay_against_real_stdio_server(tmp_path):
    pytest.importorskip("mcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    script = FIXTURES / "tiny_mcp_server.py"
    params = StdioServerParameters(
        command=sys.executable, args=[str(script)], env=dict(os.environ)
    )
    store = RecordStore(
        str(tmp_path / "r.jsonl"),
        signer=signing.Signer.generate() if signing.available() else None,
    )

    async def go():
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as ds:
                await ds.initialize()
                relay = PassiveRelay(ds, "tiny", store)
                await relay.prime()
                await relay.handle_call("delete_account", {"account_id": "a1"})
                await relay.handle_call("search_docs", {"query": "x"})

    _run(go())

    recs = read_records(str(tmp_path / "r.jsonl"))
    assert len(recs) == 2
    by_tool = {r["tool"]: r for r in recs}
    assert by_tool["delete_account"]["severity"] in ("high", "critical")
    assert by_tool["search_docs"]["severity"] == "info"


# --- posture report --------------------------------------------------------

def test_posture_summary(tmp_path):
    store = RecordStore(str(tmp_path / "r.jsonl"), signer=None)
    store.append(server="payments", tool="transfer_funds", args={}, access="write",
                 severity="critical", signals=["irreversible:transfer"])
    store.append(server="payments", tool="transfer_funds", args={}, access="write",
                 severity="critical", signals=["irreversible:transfer"])
    store.append(server="github", tool="get_file", args={}, access="read",
                 severity="info", signals=[])
    summary = summarize(read_records(str(tmp_path / "r.jsonl")))
    assert summary["total_calls"] == 3
    assert summary["by_severity"]["critical"] == 2
    assert summary["by_access"]["read"] == 1
    # payments should sort first (more risky calls) and top risky tool is the transfer.
    assert list(summary["by_server"])[0] == "payments"
    assert summary["top_risky_tools"][0]["tool"] == "payments.transfer_funds"
    assert summary["top_risky_tools"][0]["calls"] == 2
