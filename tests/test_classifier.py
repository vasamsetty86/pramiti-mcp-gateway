"""Tests for the deterministic MCP tool risk classifier."""
from __future__ import annotations

from pramiti_mcp_gateway.classifier import classify_tool


def test_read_tool_is_info():
    r = classify_tool("search_repositories", "Search for repositories.")
    assert r.access == "read"
    assert r.reversible is True
    assert r.severity == "info"
    assert r.signals == []


def test_read_of_sensitive_data_is_low():
    r = classify_tool("get_customer_ssn", "Return the customer's social security number.")
    assert r.access == "read"
    assert r.sensitive is True
    assert r.severity == "low"


def test_plain_write_is_medium():
    r = classify_tool(
        "create_pull_request",
        "Create a new pull request.",
        input_schema={"type": "object", "properties": {"title": {"type": "string"}}},
    )
    assert r.access == "write"
    assert r.severity == "medium"
    assert any(s.startswith("mutating:") for s in r.signals)


def test_irreversible_write_is_high():
    r = classify_tool(
        "delete_repository",
        "Permanently delete a repository.",
        input_schema={"type": "object", "properties": {"repo": {"type": "string"}}},
    )
    assert r.access == "write"
    assert r.reversible is False
    assert r.severity == "high"


def test_irreversible_and_sensitive_is_critical():
    r = classify_tool(
        "transfer_funds",
        "Wire funds from one account to another. Irreversible.",
        input_schema={"type": "object", "properties": {"amount": {"type": "number"}}},
    )
    assert r.access == "write"
    assert r.reversible is False
    assert r.sensitive is True
    assert r.severity == "critical"


def test_arbitrary_sql_is_critical():
    r = classify_tool(
        "run_sql",
        "Execute an arbitrary SQL query against the production database.",
        input_schema={"type": "object", "properties": {"sql": {"type": "string"}}},
    )
    assert r.overbroad is True
    assert r.severity == "critical"


def test_write_without_schema_is_flagged_overbroad():
    r = classify_tool(
        "export_patient_records",
        "Export patient medical records to a file.",
        input_schema={},
    )
    # 'export' is an irreversible/exfil verb, 'patient'/'medical' are sensitive,
    # and there is no input schema -> unconstrained.
    assert r.overbroad is True
    assert r.sensitive is True
    assert r.severity == "critical"
    assert "overbroad:no-input-schema" in r.signals


def test_camel_case_is_tokenized():
    r = classify_tool("deleteUserAccount", "Removes a user.")
    assert r.access == "write"
    assert "mutating:delete" in r.signals


def test_no_substring_false_positive():
    # 'discard' must not match the 'card' sensitive signal.
    r = classify_tool("discard_draft", "Discard an unsaved draft.")
    assert r.sensitive is False


def test_unknown_verb_defaults_to_review_not_silent():
    r = classify_tool("frobnicate_widget", "Does something unclear to a widget.")
    assert r.access == "unknown"
    assert r.severity in ("low", "medium")  # never 'info' — must be reviewed


def test_privilege_change_is_high():
    r = classify_tool(
        "grant_admin_role",
        "Grant a user the admin role.",
        input_schema={"type": "object", "properties": {"user": {"type": "string"}}},
    )
    assert r.severity in ("high", "critical")
    assert any(s.startswith("privilege:") or s.startswith("overbroad:") for s in r.signals)


def test_deterministic():
    a = classify_tool("issue_refund", "Refund a charge to the customer's credit card.")
    b = classify_tool("issue_refund", "Refund a charge to the customer's credit card.")
    assert a.to_dict() == b.to_dict()
