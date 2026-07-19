"""Passive MCP gateway: observe every tool call without blocking any of them.

The gateway is a transparent stdio proxy. An agent connects to it as if it were
the real MCP server; the gateway connects to the real server downstream and
relays traffic. It never denies a call (zero production risk) — for every
``tools/call`` it classifies the tool's risk and appends a signed, hash-chained
record, then forwards the call and returns the real result unchanged.

Install it by pointing your agent's config at the gateway instead of the server:

    "github": {
      "command": "pramiti-mcp-gateway",
      "args": ["proxy", "--server-name", "github", "--",
               "npx", "-y", "@modelcontextprotocol/server-github"]
    }

The `PassiveRelay` core (classify -> forward -> record) is transport-free and
unit-tested; ``run_proxy`` wires the MCP stdio server around it. Needs the
``mcp`` SDK (the ``connect`` extra).
"""
from __future__ import annotations

from typing import Optional

from pramiti_mcp_gateway.classifier import classify_tool
from pramiti_mcp_gateway.connect import _open_transport, select_transport
from pramiti_mcp_gateway.records import RecordStore


class PassiveRelay:
    """Classifies, forwards, and records tool calls against a downstream session.

    *downstream* is anything exposing async ``list_tools()`` and
    ``call_tool(name, arguments)`` (an ``mcp.ClientSession`` in production, a
    stub in tests).
    """

    def __init__(self, downstream, server_name: str, store: RecordStore):
        self.downstream = downstream
        self.server_name = server_name
        self.store = store
        self._tools: list = []
        self._risk: dict = {}

    async def prime(self) -> list:
        """Fetch the downstream tool set and pre-compute each tool's risk."""
        listed = await self.downstream.list_tools()
        self._tools = list(listed.tools)
        for t in self._tools:
            self._risk[t.name] = classify_tool(
                t.name,
                getattr(t, "description", "") or "",
                getattr(t, "inputSchema", None),
                self.server_name,
            )
        return self._tools

    async def handle_list(self) -> list:
        """Relay tools/list unchanged (agents see the real tools)."""
        if not self._tools:
            await self.prime()
        return self._tools

    async def handle_call(self, name: str, arguments: Optional[dict]):
        """Classify + forward + record one tool call. Never blocks."""
        risk = self._risk.get(name) or classify_tool(name, "", None, self.server_name)
        try:
            result = await self.downstream.call_tool(name, arguments or {})
        except Exception:
            self.store.append(
                server=self.server_name, tool=name, args=arguments,
                access=risk.access, severity=risk.severity, signals=risk.signals,
                outcome="error",
            )
            raise
        is_error = bool(getattr(result, "isError", False))
        self.store.append(
            server=self.server_name, tool=name, args=arguments,
            access=risk.access, severity=risk.severity, signals=risk.signals,
            outcome="error" if is_error else "forwarded",
        )
        return result


async def run_proxy(server_spec: dict, server_name: str, store: RecordStore) -> None:
    """Run the passive stdio gateway in front of one downstream server.

    *server_spec* is a server entry (``{"command": ..., "args": [...]}`` or
    ``{"url": ...}``). Blocks serving the agent until stdin closes.
    """
    from mcp import ClientSession
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server

    transport = select_transport(server_spec)
    async with _open_transport(transport) as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as downstream:
            await downstream.initialize()
            relay = PassiveRelay(downstream, server_name, store)
            await relay.prime()

            server = Server("pramiti-mcp-gateway")

            @server.list_tools()
            async def _list_tools():
                return await relay.handle_list()

            @server.call_tool()
            async def _call_tool(name: str, arguments: dict):
                result = await relay.handle_call(name, arguments)
                # Return the content blocks; the SDK re-wraps them for the agent.
                return list(getattr(result, "content", []) or [])

            async with stdio_server() as (agent_read, agent_write):
                await server.run(
                    agent_read, agent_write, server.create_initialization_options()
                )
