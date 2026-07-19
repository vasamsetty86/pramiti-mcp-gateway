"""Deterministic action-risk classifier for MCP tools.

Given only a tool's declared name, description, and input schema (the shape an
MCP ``tools/list`` response returns), classify its *action risk* along four
axes and roll them into a single severity. Pure, dependency-free, and
deterministic: the same tool always scores the same way, so results are safe to
diff in CI.

This is intentionally a heuristic. It reads only what the tool *declares* about
itself — it cannot know a server's real behavior — so it is designed to
over-flag rather than under-flag (fail-loud): an unclassifiable write is treated
as a risk, not waved through. The signal sets below are the domain model, not a
patch list; extend them as the MCP tool vocabulary grows.

The read-prefix heuristic is shared with Praxom's ``ToolActionClassifier`` so the
free scanner and the commercial control plane agree on the read/write boundary.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# --- Access: read vs write -------------------------------------------------
# Read prefixes mirror Praxom's ToolActionClassifier (get_/list_/read_/search_/
# fetch_) plus the common query verbs. A tool whose name starts with one of
# these AND carries no mutating verb is treated as read-only.
READ_PREFIXES: tuple[str, ...] = (
    "get", "list", "read", "search", "fetch",
    "query", "describe", "view", "find", "count", "lookup", "show",
)

# Verbs that indicate the tool changes state somewhere.
MUTATING_VERBS: frozenset[str] = frozenset({
    "create", "update", "delete", "remove", "drop", "write", "set", "modify",
    "edit", "insert", "upsert", "patch", "put", "post", "add", "append",
    "rename", "move", "copy", "merge", "sync", "push", "commit", "apply",
})

# --- Reversibility ---------------------------------------------------------
# Verbs whose effects are hard or impossible to undo. An irreversible action is
# the Knight-Capital class: at machine speed, with no gate, the blast radius is
# unbounded.
IRREVERSIBLE_VERBS: frozenset[str] = frozenset({
    "delete", "drop", "purge", "destroy", "terminate", "wipe", "erase",
    "send", "email", "transfer", "wire", "pay", "refund", "charge", "bill",
    "deploy", "execute", "run", "revoke", "disable", "cancel", "publish",
    "submit", "approve", "provision", "shutdown", "restart", "reset", "rollback",
    "notify", "post", "tweet", "message", "dispatch",
    # Data-exfiltration verbs. Moving data out is an action, and disclosure is
    # irreversible ("an export cannot be un-disclosed") — the classic route for
    # a prompt-injected agent to leak sensitive data through a legitimate tool.
    "export", "download", "dump", "backup", "upload", "extract",
})

# --- Sensitive data --------------------------------------------------------
# Substrings that suggest the tool reads or moves regulated / sensitive data.
# Multi-word phrases are matched as substrings of the combined text; single
# tokens are matched at word boundaries (see _matched).
SENSITIVE_SIGNALS: tuple[str, ...] = (
    "pii", "ssn", "social security", "patient", "phi", "medical", "health",
    "diagnosis", "prescription", "card", "credit", "debit", "account", "iban",
    "routing", "password", "secret", "credential", "token", "api key",
    "private key", "ssh", "salary", "payroll", "financial", "invoice",
    "payment", "transaction", "customer", "personal", "address", "passport",
    "license", "biometric", "gdpr", "hipaa", "confidential", "classified",
)

# --- Over-broad power ------------------------------------------------------
# Signals that a tool grants arbitrary, un-scoped capability — the confused
# deputy's favorite target. These escalate severity regardless of read/write.
OVERBROAD_SIGNALS: tuple[str, ...] = (
    "exec", "eval", "shell", "bash", "command", "cmd", "script", "sql",
    "raw", "arbitrary", "any", "admin", "root", "sudo", "superuser",
    "database", "query database", "run code", "system",
)

# Privilege / access-control verbs — changing who can do what is high impact.
PRIVILEGE_SIGNALS: tuple[str, ...] = (
    "grant", "revoke", "permission", "role", "policy", "acl", "iam",
    "privilege", "authorize", "disable user", "enable user",
)

SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


def _severity_max(*levels: str) -> str:
    """Return the highest severity among *levels* (by SEVERITY_ORDER)."""
    idx = max((SEVERITY_ORDER.index(lv) for lv in levels if lv in SEVERITY_ORDER), default=0)
    return SEVERITY_ORDER[idx]


@dataclass
class ToolRisk:
    """The risk assessment for a single MCP tool."""

    name: str
    server: str = ""
    access: str = "unknown"           # "read" | "write" | "unknown"
    reversible: Optional[bool] = None  # None = unknown / not applicable
    sensitive: bool = False
    overbroad: bool = False
    severity: str = "info"             # info | low | medium | high | critical
    signals: list[str] = field(default_factory=list)   # matched risk signals
    rationale: str = ""

    @property
    def qualified_name(self) -> str:
        return f"{self.server}.{self.name}" if self.server else self.name

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "server": self.server,
            "qualified_name": self.qualified_name,
            "access": self.access,
            "reversible": self.reversible,
            "sensitive": self.sensitive,
            "overbroad": self.overbroad,
            "severity": self.severity,
            "signals": list(self.signals),
            "rationale": self.rationale,
        }


_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _tokens(name: str) -> list[str]:
    """Split a tool name into lowercase tokens across camelCase and separators.

    ``createInvoicePayment`` -> ['create', 'invoice', 'payment']
    ``delete_user_account``  -> ['delete', 'user', 'account']
    """
    spaced = _CAMEL_BOUNDARY.sub(" ", name)
    return [t for t in _NON_ALNUM.split(spaced.lower()) if t]


def _matched(text: str, tokens: set[str], signals) -> list[str]:
    """Return the signals present in *text*.

    Single-word signals match against *tokens* (word boundaries, no false
    substring hits like 'card' in 'discard'). Multi-word signals match as
    substrings of the lowercased *text*.
    """
    hits: list[str] = []
    for sig in signals:
        if " " in sig:
            if sig in text:
                hits.append(sig)
        elif sig in tokens:
            hits.append(sig)
    return hits


def _has_schema_constraints(input_schema: Optional[dict]) -> bool:
    """True if the tool declares any argument shape at all.

    A write tool with no declared properties accepts free-form input — the
    caller (a possibly-injected agent) fully controls what it does.
    """
    if not isinstance(input_schema, dict):
        return False
    props = input_schema.get("properties")
    return bool(props) if isinstance(props, (dict, list)) else False


def classify_tool(
    name: str,
    description: str = "",
    input_schema: Optional[dict] = None,
    server: str = "",
) -> ToolRisk:
    """Classify a single MCP tool's action risk.

    Only the tool's self-declared metadata is used. Unknown / unclassifiable
    non-read tools are treated as a risk (fail-loud), never waved through.
    """
    name = name or ""
    description = description or ""
    combined = f"{name} {description}".lower()
    name_tokens = set(_tokens(name))
    # Description contributes tokens too, so "Deletes the account" flags even if
    # the tool is blandly named "account_op".
    all_tokens = name_tokens | set(_tokens(description))

    mutating_hits = sorted(all_tokens & MUTATING_VERBS)
    irreversible_hits = sorted(all_tokens & IRREVERSIBLE_VERBS)
    sensitive_hits = _matched(combined, all_tokens, SENSITIVE_SIGNALS)
    overbroad_hits = _matched(combined, all_tokens, OVERBROAD_SIGNALS)
    privilege_hits = _matched(combined, all_tokens, PRIVILEGE_SIGNALS)

    first_token = next(iter(_tokens(name)), "")
    starts_read = first_token in READ_PREFIXES

    # Access: a read prefix wins only when nothing mutating is present.
    if mutating_hits or irreversible_hits or privilege_hits:
        access = "write"
    elif starts_read:
        access = "read"
    else:
        access = "unknown"

    reversible: Optional[bool]
    if access == "read":
        reversible = True
    elif irreversible_hits:
        reversible = False
    elif access == "write":
        reversible = None  # write, but no explicit irreversible verb
    else:
        reversible = None

    sensitive = bool(sensitive_hits)
    # A write tool with no declared argument schema is effectively open-ended.
    unconstrained_write = access == "write" and not _has_schema_constraints(input_schema)
    overbroad = bool(overbroad_hits) or unconstrained_write

    # --- Severity ---------------------------------------------------------
    if access == "read":
        severity = "low" if sensitive else "info"
    elif access == "write":
        if reversible is False and sensitive:
            severity = "critical"
        elif reversible is False or sensitive:
            severity = "high"
        else:
            severity = "medium"
    else:  # unknown: not a clear read, no clear write verb — review it
        severity = "medium" if sensitive else "low"

    # Over-broad execution power is critical regardless of read/write framing:
    # an exec/sql/shell tool is a universal action primitive.
    if overbroad_hits:
        severity = _severity_max(severity, "critical")
    elif unconstrained_write:
        severity = _severity_max(severity, "high")
    if privilege_hits:
        severity = _severity_max(severity, "high")

    signals: list[str] = []
    signals += [f"mutating:{v}" for v in mutating_hits]
    signals += [f"irreversible:{v}" for v in irreversible_hits]
    signals += [f"sensitive:{s}" for s in sensitive_hits]
    signals += [f"overbroad:{s}" for s in overbroad_hits]
    signals += [f"privilege:{s}" for s in privilege_hits]
    if unconstrained_write:
        signals.append("overbroad:no-input-schema")

    rationale = _rationale(access, reversible, sensitive, overbroad, signals)

    return ToolRisk(
        name=name,
        server=server,
        access=access,
        reversible=reversible,
        sensitive=sensitive,
        overbroad=overbroad,
        severity=severity,
        signals=signals,
        rationale=rationale,
    )


def _rationale(access, reversible, sensitive, overbroad, signals) -> str:
    if not signals and access == "read":
        return "Read-only tool; no state change or sensitive-data signals detected."
    parts: list[str] = []
    if access == "write":
        parts.append("changes state")
    elif access == "unknown":
        parts.append("unclassified action verb — review manually")
    if reversible is False:
        parts.append("effects are hard to reverse")
    if sensitive:
        parts.append("touches sensitive/regulated data")
    if overbroad:
        parts.append("grants broad or unconstrained capability")
    return "; ".join(parts).capitalize() + "." if parts else "No notable risk signals."
