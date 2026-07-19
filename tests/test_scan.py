"""Tests for the manifest scanner and posture report."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pramiti_mcp_gateway.scan import render_text, scan_manifest

SAMPLE = Path(__file__).resolve().parents[1] / "examples" / "tools.sample.json"


def test_scan_sample_manifest():
    manifest = json.loads(SAMPLE.read_text())
    report = scan_manifest(manifest)
    assert len(report.tools) == 9
    # The sample has arbitrary SQL, an irreversible sensitive transfer, and an
    # unconstrained PHI export -> at least three criticals.
    assert report.counts["critical"] >= 3
    assert report.max_severity() == "critical"


def test_scan_sorts_worst_first():
    manifest = json.loads(SAMPLE.read_text())
    report = scan_manifest(manifest)
    severities = [t.severity for t in report.tools]
    # Non-increasing severity order.
    from pramiti_mcp_gateway.classifier import SEVERITY_ORDER
    ranks = [SEVERITY_ORDER.index(s) for s in severities]
    assert ranks == sorted(ranks, reverse=True)


def test_bare_list_shape():
    report = scan_manifest([{"name": "get_thing", "description": "reads a thing"}])
    assert len(report.tools) == 1
    assert report.tools[0].access == "read"


def test_tools_list_shape():
    report = scan_manifest({"tools": [{"name": "delete_thing"}], "server": "svc"})
    assert report.tools[0].server == "svc"
    assert report.tools[0].access == "write"


def test_mcp_config_shape_gives_actionable_error():
    with pytest.raises(ValueError, match="mcpServers"):
        scan_manifest({"mcpServers": {"github": {"command": "npx"}}})


def test_unnamed_tools_skipped():
    report = scan_manifest([{"description": "no name"}, {"name": "get_x"}])
    assert len(report.tools) == 1


def test_render_text_contains_summary_and_worst():
    manifest = json.loads(SAMPLE.read_text())
    text = render_text(scan_manifest(manifest))
    assert "MCP Security Posture" in text
    assert "9 tools scanned" in text
    assert "Top risk: CRITICAL" in text


def test_report_to_dict_roundtrips_json():
    manifest = json.loads(SAMPLE.read_text())
    d = scan_manifest(manifest).to_dict()
    # Must be JSON-serializable.
    json.dumps(d)
    assert d["summary"]["total_tools"] == 9
