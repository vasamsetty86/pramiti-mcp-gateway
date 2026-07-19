"""Turn a gateway record log into an "MCP posture over time" report.

Answers the question a security owner actually asks: over this window, what did
my agents *do* — how many high-risk actions, through which servers, which tools
most often? Reads the signed record chain (raw args never appear; only their
hashes and the risk classification snapshot were stored).
"""
from __future__ import annotations

from collections import Counter, defaultdict

from pramiti_mcp_gateway.classifier import SEVERITY_ORDER


def summarize(records: list) -> dict:
    by_severity: Counter = Counter()
    by_access: Counter = Counter()
    per_server: dict = defaultdict(lambda: {"calls": 0, "risky": 0})
    tool_calls: Counter = Counter()
    tool_severity: dict = {}
    timestamps: list = []

    for rec in records:
        sev = rec.get("severity", "info")
        acc = rec.get("access", "unknown")
        server = rec.get("server", "")
        tool = rec.get("tool", "")
        qname = f"{server}.{tool}" if server else tool

        by_severity[sev] += 1
        by_access[acc] += 1
        per_server[server]["calls"] += 1
        if sev in ("critical", "high"):
            per_server[server]["risky"] += 1
        tool_calls[qname] += 1
        # Keep the highest severity ever seen for this tool.
        if qname not in tool_severity or _rank(sev) > _rank(tool_severity[qname]):
            tool_severity[qname] = sev
        if rec.get("ts"):
            timestamps.append(rec["ts"])

    # Top risky tools: order by severity, then by how often they were called.
    ranked = sorted(
        tool_calls.keys(),
        key=lambda q: (-_rank(tool_severity.get(q, "info")), -tool_calls[q], q),
    )
    top_risky = [
        {
            "tool": q,
            "severity": tool_severity.get(q, "info"),
            "calls": tool_calls[q],
        }
        for q in ranked
        if _rank(tool_severity.get(q, "info")) >= _rank("medium")
    ]

    return {
        "total_calls": len(records),
        "window": {
            "first": min(timestamps) if timestamps else None,
            "last": max(timestamps) if timestamps else None,
        },
        "by_severity": {lv: by_severity.get(lv, 0) for lv in SEVERITY_ORDER},
        "by_access": {
            "read": by_access.get("read", 0),
            "write": by_access.get("write", 0),
            "unknown": by_access.get("unknown", 0),
        },
        "by_server": {
            s: dict(v) for s, v in sorted(per_server.items(), key=lambda kv: -kv[1]["risky"])
        },
        "top_risky_tools": top_risky,
    }


def _rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 0


def render_text(summary: dict) -> str:
    lines: list[str] = []
    lines.append("MCP Posture Over Time")
    lines.append("=" * 60)
    w = summary["window"]
    if w["first"]:
        lines.append(f"window: {w['first']}  ->  {w['last']}")
    s = summary["by_severity"]
    a = summary["by_access"]
    lines.append(
        f"{summary['total_calls']} tool calls observed  |  "
        f"read {a['read']}  write {a['write']}  unknown {a['unknown']}"
    )
    lines.append(
        f"severity:  critical {s['critical']}  high {s['high']}  "
        f"medium {s['medium']}  low {s['low']}  info {s['info']}"
    )
    lines.append("-" * 60)
    if summary["by_server"]:
        lines.append("by server (risky = critical+high calls):")
        for server, v in summary["by_server"].items():
            label = server or "(unnamed)"
            lines.append(f"  {label:<24} {v['calls']:>5} calls   {v['risky']:>4} risky")
        lines.append("-" * 60)
    if summary["top_risky_tools"]:
        lines.append("most-called risky tools:")
        for t in summary["top_risky_tools"][:15]:
            lines.append(f"  [{t['severity']:<8}] {t['tool']}  x{t['calls']}")
    else:
        lines.append("no medium-or-higher risk tool calls observed.")
    return "\n".join(lines)
