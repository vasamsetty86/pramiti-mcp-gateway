"""Tests for live-connect: config parsing, transport selection, error routing,
and one real end-to-end scan against a tiny MCP server over stdio.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from pramiti_mcp_gateway import connect
from pramiti_mcp_gateway.scan import scan_manifest

FIXTURES = Path(__file__).resolve().parent / "fixtures"


# --- config parsing --------------------------------------------------------

def test_load_config_mcpservers(tmp_path):
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps({"mcpServers": {"a": {"command": "x"}}}))
    assert connect.load_config(str(p)) == {"a": {"command": "x"}}


def test_load_config_servers_alias(tmp_path):
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps({"servers": {"a": {"url": "http://x"}}}))
    assert "a" in connect.load_config(str(p))


def test_load_config_empty_is_error(tmp_path):
    p = tmp_path / "cfg.json"
    p.write_text(json.dumps({"mcpServers": {}}))
    with pytest.raises(ValueError, match="mcpServers"):
        connect.load_config(str(p))


# --- transport selection (pure) --------------------------------------------

def test_select_stdio():
    t = connect.select_transport({"command": "npx", "args": ["-y", "srv"], "env": {"K": "v"}})
    assert t == {"kind": "stdio", "command": "npx", "args": ["-y", "srv"], "env": {"K": "v"}}


def test_select_sse_by_suffix():
    assert connect.select_transport({"url": "https://x.com/sse"})["kind"] == "sse"


def test_select_sse_by_type():
    assert connect.select_transport({"url": "https://x.com/x", "type": "sse"})["kind"] == "sse"


def test_select_http_default():
    assert connect.select_transport({"url": "https://x.com/mcp"})["kind"] == "http"


def test_select_neither_is_error():
    with pytest.raises(ValueError, match="neither"):
        connect.select_transport({"foo": "bar"})


# --- error routing (one bad server does not abort the scan) ----------------

def test_discover_routes_per_server_errors(monkeypatch):
    async def fake_discover_one(spec):
        if spec.get("command") == "bad":
            raise RuntimeError("boom")
        return [{"name": "get_thing", "description": "reads a thing"}]

    monkeypatch.setattr(connect, "_discover_one", fake_discover_one)
    manifest, errors = connect.discover(
        {"good": {"command": "ok"}, "bad": {"command": "bad"}}, timeout=5.0
    )
    assert "bad" in errors and "boom" in errors["bad"]
    assert errors.get("good") is None
    assert manifest["servers"]["good"]["tools"][0]["name"] == "get_thing"
    assert manifest["servers"]["bad"]["tools"] == []


# --- real end-to-end scan over stdio ---------------------------------------

def test_live_scan_against_real_stdio_server():
    """Connect to a real MCP server subprocess, enumerate, classify."""
    pytest.importorskip("mcp")
    script = FIXTURES / "tiny_mcp_server.py"
    servers = {
        "tiny": {
            "command": sys.executable,
            "args": [str(script)],
            "env": dict(os.environ),  # ensure the child can import mcp
        }
    }
    manifest, errors = connect.discover(servers, timeout=30.0)
    assert errors == {}, errors

    report = scan_manifest(manifest)
    by_name = {t.name: t for t in report.tools}
    assert set(by_name) == {"search_docs", "delete_account"}

    assert by_name["search_docs"].access == "read"
    assert by_name["search_docs"].severity == "info"

    assert by_name["delete_account"].access == "write"
    assert by_name["delete_account"].reversible is False
    assert by_name["delete_account"].severity in ("high", "critical")
