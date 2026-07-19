"""Live connect: discover an MCP server's real tools by connecting to it.

Given a standard MCP client config (the ``mcpServers`` shape used by Claude
Desktop, Cursor, etc.), connect to each configured server, call ``tools/list``,
and return a manifest the offline scanner can classify. Supports both stdio
(local subprocess) and remote (SSE / streamable-HTTP) transports.

``list_tools`` is a read-only protocol call — it never executes a tool. But
scanning a **stdio** server does launch its process (that is the only way to
speak the protocol to it), so this connects only to servers you configured
yourself.

The ``mcp`` SDK is an OPTIONAL dependency (the ``connect`` extra). It is imported
lazily so the offline ``scan`` path stays zero-dependency.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

_MCP_MISSING = (
    "live connect needs the MCP SDK. Install it with:\n"
    "    pip install 'pramiti-mcp-gateway[connect]'\n"
    "or scan an offline tools manifest instead (no dependency required)."
)


def _require_mcp() -> None:
    try:
        import mcp  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise RuntimeError(_MCP_MISSING) from exc


def load_config(path: str) -> dict:
    """Load an MCP client config and return its server map.

    Accepts the standard ``{"mcpServers": {...}}`` shape (Claude Desktop /
    Cursor) and the plain ``{"servers": {...}}`` alias.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("config must be a JSON object")
    servers = raw.get("mcpServers")
    if servers is None:
        servers = raw.get("servers")
    if not isinstance(servers, dict) or not servers:
        raise ValueError(
            "config has no 'mcpServers' map — expected "
            "{'mcpServers': {'<name>': {'command'|'url': ...}}}"
        )
    return servers


def select_transport(spec: dict) -> dict:
    """Decide which transport a server spec uses. Pure; no ``mcp`` import.

    Returns a dict with ``kind`` in {'stdio', 'sse', 'http'} plus its params.
    Raises ValueError if the spec declares neither a command nor a url.
    """
    if not isinstance(spec, dict):
        raise ValueError("server spec must be an object")
    command = spec.get("command")
    if command:
        return {
            "kind": "stdio",
            "command": command,
            "args": list(spec.get("args") or []),
            "env": spec.get("env") or None,
        }
    url = spec.get("url")
    if url:
        ttype = str(spec.get("type") or spec.get("transport") or "").lower()
        if ttype == "sse" or (not ttype and url.rstrip("/").lower().endswith("sse")):
            return {"kind": "sse", "url": url}
        return {"kind": "http", "url": url}
    raise ValueError("server has neither 'command' (stdio) nor 'url' (remote)")


def _tool_to_dict(tool) -> dict:
    """Normalize an MCP SDK Tool into the manifest shape the scanner reads."""
    out = {
        "name": tool.name,
        "description": getattr(tool, "description", "") or "",
        "inputSchema": getattr(tool, "inputSchema", None),
    }
    ann = getattr(tool, "annotations", None)
    if ann is not None:
        # Preserve MCP tool annotations (readOnlyHint, destructiveHint, ...)
        # for future use; the current classifier ignores unknown keys.
        out["annotations"] = ann.model_dump() if hasattr(ann, "model_dump") else ann
    return out


def _open_transport(t: dict):
    """Build the async transport context manager for a selected transport."""
    if t["kind"] == "stdio":
        from mcp import StdioServerParameters
        from mcp.client.stdio import stdio_client

        return stdio_client(
            StdioServerParameters(command=t["command"], args=t["args"], env=t["env"])
        )
    if t["kind"] == "sse":
        from mcp.client.sse import sse_client

        return sse_client(t["url"])
    from mcp.client.streamable_http import streamablehttp_client

    return streamablehttp_client(t["url"])


async def _discover_one(spec: dict) -> list[dict]:
    """Connect to one server, initialize, and return its tools as dicts."""
    from mcp import ClientSession

    transport = select_transport(spec)
    async with _open_transport(transport) as streams:
        # stdio/sse yield (read, write); streamable-http yields a 3-tuple.
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            return [_tool_to_dict(t) for t in result.tools]


async def discover_server(
    name: str, spec: dict, timeout: float
) -> tuple[list[dict], Optional[str]]:
    """Discover one server's tools. Returns (tools, error_message).

    A failing server (bad command, unreachable url, timeout, protocol error)
    yields ([], "<reason>") rather than aborting the whole scan.
    """
    try:
        tools = await asyncio.wait_for(_discover_one(spec), timeout)
        return tools, None
    except asyncio.TimeoutError:
        return [], f"timed out after {timeout:g}s"
    except Exception as exc:  # noqa: BLE001 - report any failure per-server
        return [], f"{type(exc).__name__}: {exc}"


async def discover_all(servers: dict, timeout: float) -> tuple[dict, dict]:
    """Discover every server concurrently. Returns (manifest, errors)."""
    names = list(servers)
    results = await asyncio.gather(
        *(discover_server(n, servers[n], timeout) for n in names)
    )
    manifest: dict = {"servers": {}}
    errors: dict = {}
    for name, (tools, err) in zip(names, results):
        manifest["servers"][name] = {"tools": tools}
        if err:
            errors[name] = err
    return manifest, errors


def discover(servers: dict, timeout: float = 30.0) -> tuple[dict, dict]:
    """Sync entry point: connect to *servers* and return (manifest, errors).

    Raises RuntimeError with install guidance if the ``mcp`` SDK is missing.
    """
    _require_mcp()
    return asyncio.run(discover_all(servers, timeout))
