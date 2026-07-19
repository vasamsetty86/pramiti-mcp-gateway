"""Scan a manifest of MCP tools and produce a security posture report.

The scanner is offline and deterministic: it takes tools that an MCP server
*declares* (the shape of an MCP ``tools/list`` result) and classifies each one.
It never launches or connects to a server, so it is safe to run anywhere,
including CI, with zero infrastructure.

Accepted manifest shapes (all normalized internally):

- a raw ``tools/list`` result:            ``{"tools": [ {name, description, inputSchema}, ... ]}``
- a bare list of tools:                   ``[ {name, ...}, ... ]``
- multi-server:                           ``{"servers": {"github": {"tools": [...]}, ...}}``
- the common MCP client-config shape with an embedded per-server tools list.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from pramiti_mcp_gateway.classifier import SEVERITY_ORDER, ToolRisk, classify_tool


@dataclass
class PostureReport:
    """The result of scanning one or more MCP servers' tool sets."""

    tools: list[ToolRisk] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        """Tool counts keyed by severity (every level present, even if zero)."""
        out = {level: 0 for level in SEVERITY_ORDER}
        for t in self.tools:
            out[t.severity] = out.get(t.severity, 0) + 1
        return out

    @property
    def access_counts(self) -> dict[str, int]:
        out = {"read": 0, "write": 0, "unknown": 0}
        for t in self.tools:
            out[t.access] = out.get(t.access, 0) + 1
        return out

    def max_severity(self) -> str:
        idx = max((SEVERITY_ORDER.index(t.severity) for t in self.tools), default=0)
        return SEVERITY_ORDER[idx]

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total_tools": len(self.tools),
                "by_severity": self.counts,
                "by_access": self.access_counts,
                "max_severity": self.max_severity(),
            },
            "tools": [t.to_dict() for t in self.tools],
        }


def _iter_server_tools(manifest) -> Iterable[tuple[str, list]]:
    """Yield (server_name, tools_list) pairs from any accepted manifest shape."""
    if isinstance(manifest, list):
        yield "", manifest
        return
    if not isinstance(manifest, dict):
        raise ValueError(
            "unrecognized manifest: expected a list of tools, a "
            "{'tools': [...]} object, or a {'servers': {...}} object"
        )
    if "servers" in manifest and isinstance(manifest["servers"], dict):
        for server_name, entry in manifest["servers"].items():
            tools = entry.get("tools", []) if isinstance(entry, dict) else []
            yield str(server_name), list(tools)
        return
    if "tools" in manifest and isinstance(manifest["tools"], list):
        yield str(manifest.get("server", "")), list(manifest["tools"])
        return
    # mcpServers config shape (Claude Desktop / Cursor): tools aren't in the
    # config (they're discovered at runtime), so there's nothing to scan
    # offline. Be explicit rather than silently returning empty.
    if "mcpServers" in manifest:
        raise ValueError(
            "this looks like an MCP client config (mcpServers). It lists servers "
            "but not their tools — tools are discovered by connecting. Run "
            "`pramiti-mcp-gateway scan --config <file>` (requires the 'connect' "
            "extra) to connect and enumerate, or pass a tools/list manifest."
        )
    raise ValueError(
        "unrecognized manifest object: expected 'tools' or 'servers' key"
    )


def scan_manifest(manifest) -> PostureReport:
    """Classify every tool in *manifest* and return a PostureReport."""
    report = PostureReport()
    for server_name, tools in _iter_server_tools(manifest):
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name") or ""
            if not name:
                continue
            report.tools.append(
                classify_tool(
                    name=name,
                    description=tool.get("description", ""),
                    input_schema=tool.get("inputSchema") or tool.get("input_schema"),
                    server=server_name,
                )
            )
    # Highest severity first, then by server/name for stable output.
    report.tools.sort(
        key=lambda t: (-SEVERITY_ORDER.index(t.severity), t.server, t.name)
    )
    return report


# --- Rendering -------------------------------------------------------------

_SEVERITY_BADGE = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def render_text(report: PostureReport, *, color: bool = False) -> str:
    """Human-readable posture report for the terminal."""
    lines: list[str] = []
    s = report.to_dict()["summary"]
    lines.append("MCP Security Posture")
    lines.append("=" * 60)
    lines.append(
        f"{s['total_tools']} tools scanned  |  "
        f"read {report.access_counts['read']}  "
        f"write {report.access_counts['write']}  "
        f"unknown {report.access_counts['unknown']}"
    )
    c = report.counts
    lines.append(
        f"severity:  critical {c['critical']}  high {c['high']}  "
        f"medium {c['medium']}  low {c['low']}  info {c['info']}"
    )
    lines.append("-" * 60)
    for t in report.tools:
        badge = _SEVERITY_BADGE.get(t.severity, t.severity.upper())
        lines.append(f"[{badge}] {t.qualified_name}")
        if t.rationale:
            lines.append(f"        {t.rationale}")
        if t.signals:
            lines.append(f"        signals: {', '.join(t.signals)}")
    lines.append("-" * 60)
    worst = report.max_severity()
    if worst in ("critical", "high"):
        lines.append(
            f"Top risk: {worst.upper()}. These tools let an agent take "
            "high-impact actions. Gate them before giving an agent write access."
        )
    else:
        lines.append("No high-severity action tools detected in this set.")
    return "\n".join(lines)
