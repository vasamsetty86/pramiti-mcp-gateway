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


def test_a_server_entry_that_is_a_plain_tool_list_is_not_silently_clean():
    """Ship-surface fourth pass, F4-2 (HIGH) — in the free OSS scanner.

    `_iter_server_tools` did `entry.get("tools", []) if isinstance(entry, dict)
    else []`, so any server entry that was not a dict carrying a "tools" list
    contributed ZERO tools. `{"servers": {"db": [run_shell, delete_account]}}`
    reported 0 tools and a clean posture, exit 0, while the same two tools in the
    accepted spelling score high and exit 2.

    The shape is not exotic: this module's own error text tells the user to pass
    `{'servers': {...}}`, which invites exactly this spelling.
    """
    report = scan_manifest({"servers": {"db": [
        {"name": "run_shell", "description": "Execute an arbitrary shell command."},
        {"name": "delete_account", "description": "Permanently delete an account."},
    ]}})
    assert len(report.tools) == 2, (
        "the scanner saw no tools and would have reported a clean stack"
    )


def test_an_unreadable_server_entry_is_reported_not_silently_dropped():
    """It must not be silently clean, and must not kill the whole scan either."""
    report = scan_manifest({"servers": {
        "good": {"tools": [
            {"name": "run_shell", "description": "Execute an arbitrary shell command."}
        ]},
        "weird": {"cmd": "npx", "args": ["srv"]},
    }})
    assert len(report.tools) == 1, "one odd entry threw away the readable server"
    assert "weird" in report.unreadable
    assert report.to_dict()["summary"]["unreadable_servers"] == 1
    assert "UNREADABLE" in render_text(report)


def test_an_empty_server_entry_is_an_honest_zero():
    report = scan_manifest({"servers": {"db": {}}})
    assert len(report.tools) == 0


def test_gateway_scan_cli_exit_0_requires_that_something_was_inspected(tmp_path, capsys):
    """The same rule as agentguard's scanner — this CLI had it too.

    `report.tools` empty returned 0 even when every server was unreadable, so a
    manifest the scanner never saw produced a reassuring report and a passing CI
    gate. An EMPTY stack is still 0; only a failure to read is not.
    """
    import json as _json

    from pramiti_mcp_gateway.cli import main

    unreadable = tmp_path / "unreadable.json"
    unreadable.write_text(_json.dumps({"servers": {"db": {"command": "npx"}}}))
    assert main(["scan", str(unreadable)]) == 1
    assert "NO POSTURE" in capsys.readouterr().err

    empty = tmp_path / "empty.json"
    empty.write_text(_json.dumps({"servers": {}}))
    assert main(["scan", str(empty)]) == 0, "an honestly empty stack must stay 0"


def test_unreachable_servers_reach_the_exit_gate_on_the_connect_path(tmp_path, capsys):
    """Sixth pass S6-1 (HIGH). The gate covered the offline path only.

    `discover()`'s connect failures go to a separate `errors` dict that was
    printed as warnings and never reached the exit gate, so
    `pramiti-mcp-gateway scan --config <cfg>` with ZERO servers reachable printed
    "No high-severity action tools detected" and exited 0 — on the path this
    package's own error text tells users to run, in a package already on PyPI.
    """
    import json as _json

    from pramiti_mcp_gateway.cli import main

    cfg = tmp_path / "mcp.json"
    cfg.write_text(_json.dumps({"mcpServers": {
        "ghost": {"command": "/nonexistent/binary-that-does-not-exist", "args": []}
    }}))

    code = main(["scan", "--config", str(cfg), "--timeout", "5"])
    captured = capsys.readouterr()

    assert code == 1, (
        "a stack the scanner never reached was reported clean:\n" + captured.out
    )
    assert "No high-severity action tools detected" not in captured.out, (
        "a reassuring verdict was printed beside a failing exit code"
    )
    assert "NO POSTURE" in captured.out


def test_tool_entries_of_an_unreadable_shape_are_recorded(tmp_path):
    """Sixth pass. P5-4 had been applied to agentguard's scanner only, so the two
    reached OPPOSITE verdicts on identical bytes."""
    report = scan_manifest({"servers": {"db": ["run_shell", "delete_account"]}})
    assert len(report.tools) == 0
    assert len(report.unreadable) == 2


def _scanner_exit_codes(tmp_path, shape, label):
    """Run BOTH real CLIs over the same bytes and return their exit codes.

    Earlier this test retyped the gate condition in Python instead of invoking
    the CLIs, so it agreed with an implementation rather than with observed
    behaviour. Drive the actual entry points.
    """
    import json as _json

    from pramiti_agentguard.cli import main as ag_main
    from pramiti_mcp_gateway.cli import main as gw_main

    path = tmp_path / f"{label}.json"
    path.write_text(_json.dumps(shape))
    return gw_main(["scan", str(path)]), ag_main(["scan", str(path)])


# Every shape the two scanners must agree on. The nameless/empty-name entries are
# here because they were NOT: the seventh pass showed that deleting the
# empty-name branch from the gateway left both suites green, so the "all four
# mutation-verified" claim on that commit was wrong for that branch.
AGREEMENT_SHAPES = [
    ("plain_list", {"servers": {"db": ["run_shell"]}}),
    ("unreadable_entry", {"servers": {"db": {"command": "npx"}}}),
    ("empty_servers", {"servers": {}}),
    ("empty_tools", {"servers": {"db": {"tools": []}}}),
    ("real_tool", {"servers": {"db": {"tools": [
        {"name": "run_shell", "description": "Execute an arbitrary shell command."}
    ]}}}),
    ("nameless_tools", {"tools": [{"description": "nameless"}, {"name": ""}]}),
    ("nameless_in_server", {"servers": {"db": [{"description": "nameless"}]}}),
    ("empty_name_in_server", {"servers": {"db": [{"name": ""}]}}),
    ("mixed_named_and_nameless", {"servers": {"db": [
        {"name": "run_shell", "description": "Execute an arbitrary shell command."},
        {"name": ""},
    ]}}),
]


@pytest.mark.parametrize(("label", "shape"), AGREEMENT_SHAPES)
def test_both_scanners_agree_on_whether_they_could_see_anything(
    tmp_path, label, shape
):
    """The invariant that kept being applied to one scanner and not the other.

    NOT "identical exit codes": the two CLIs have deliberately different risk
    POLICIES — the gateway only fails with `--fail-on`, agentguard fails by
    default on CI_FAILING_TIERS. Asserting equality there would encode an
    intentional difference as a defect (an earlier draft of this test did, and
    was wrong).

    What must agree is whether the scanner could SEE anything at all. Exit 1
    means "I could not look" in both, and that is the rule that has been applied
    in one place and missed in the other, round after round.
    """
    gw_code, ag_code = _scanner_exit_codes(tmp_path, shape, label)
    assert (gw_code == 1) == (ag_code == 1), (
        f"blindness disagreement on {label}: gateway exit {gw_code}, "
        f"agentguard exit {ag_code} — one reported a posture for bytes the "
        f"other refused to read"
    )


@pytest.mark.parametrize(("label", "shape"), AGREEMENT_SHAPES)
def test_both_scanners_find_the_same_dangerous_tools(tmp_path, label, shape):
    """Policy may differ; DETECTION may not."""
    from pramiti_agentguard.scan_policy import CI_FAILING_TIERS, scan_report

    gw = scan_manifest(shape)
    ag = scan_report(shape)

    gw_dangerous = gw.max_severity() in ("critical", "high") and bool(gw.tools)
    ag_dangerous = any(
        tool["tier"] in CI_FAILING_TIERS
        for entry in ag["servers"].values()
        for tool in entry["tools"]
    )
    assert gw_dangerous == ag_dangerous, (
        f"{label}: gateway sees danger={gw_dangerous}, agentguard={ag_dangerous}"
    )


@pytest.mark.parametrize(("label", "shape"), AGREEMENT_SHAPES)
def test_both_scanners_count_the_same_tools(tmp_path, label, shape):
    """Same bytes, same number of tools actually classified."""
    from pramiti_agentguard.scan_policy import scan_report

    gw = len(scan_manifest(shape).tools)
    ag = scan_report(shape)["summary"]["total_tools"]
    assert gw == ag, f"{label}: gateway classified {gw} tools, agentguard {ag}"


@pytest.mark.parametrize(("label", "shape"), AGREEMENT_SHAPES)
def test_neither_scanner_reports_clean_on_a_tool_it_could_not_read(
    tmp_path, label, shape
):
    """An unreadable tool must never contribute to a reassuring verdict."""
    from pramiti_agentguard.scan_policy import scan_report

    gw = scan_manifest(shape)
    ag = scan_report(shape)

    gw_blind = bool(gw.unreadable) and not gw.tools
    ag_blind = ag["exit_code"] == 1
    assert gw_blind == ag_blind, (
        f"{label}: gateway blind={gw_blind}, agentguard blind={ag_blind}"
    )
    if gw.unreadable and not gw.tools:
        assert "NO POSTURE" in render_text(gw), label
