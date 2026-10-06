"""Record format v2: policy decisions and a risk tier inside the signed payload.

WHY THE FORMAT GREW
-------------------
v1 records what a tool call WAS (server, tool, args hash, risk axes, outcome).
That is enough for the passive gateway, which never decides anything. An active
gateway also has to record what it DID and why — which policies ran, what each
one returned, and the tier the decision was based on. Leaving that outside the
payload would leave the most audit-relevant fields unsigned and unchained: an
"approved" that nothing protects is not evidence.

COMPATIBILITY IS A CORRECTNESS PROPERTY, NOT A COURTESY
-------------------------------------------------------
Existing logs on disk were hashed over the v1 field tuple. Verification
therefore dispatches on the record's own `version` field, and a chain may mix
both — a gateway upgraded mid-session writes v1 then v2 into one file, and that
file must still verify end to end.

The dispatch also has to resist being used as a downgrade: stripping `version`
from a v2 record, or bolting it onto a v1 record, must both surface as
verification failures rather than as a quietly re-interpreted payload.
"""
from __future__ import annotations

import json

import pytest

from pramiti_mcp_gateway import signing
from pramiti_mcp_gateway.records import (
    PAYLOAD_FIELDS,
    PAYLOAD_FIELDS_V2,
    RECORD_VERSION,
    RecordStore,
    read_records,
)
from pramiti_mcp_gateway.verify import verify_records

DECISIONS = [
    {"policy": "scan", "decision": "allow", "reason": ""},
    {"policy": "budget", "decision": "allow", "reason": "budget_check_failed"},
    {"policy": "guard", "decision": "deny", "reason": "approval_timeout"},
]


def _signer():
    return signing.Signer.generate() if signing.available() else None


def test_v2_payload_fields_extend_v1_without_reordering_it():
    """v1 field order is load-bearing — canonical() sorts keys, but the tuple is
    the shared contract with verify.py and must stay a strict extension."""
    assert PAYLOAD_FIELDS_V2[: len(PAYLOAD_FIELDS)] == PAYLOAD_FIELDS
    assert set(PAYLOAD_FIELDS_V2) - set(PAYLOAD_FIELDS) == {
        "classification",
        "decisions",
        "version",
    }


def test_appending_without_the_new_fields_still_writes_v1(tmp_path):
    """The passive gateway must keep producing byte-identical v1 records."""
    store = RecordStore(str(tmp_path / "rec.jsonl"), signer=_signer())
    rec = store.append(
        server="s", tool="get_x", args={"id": 1},
        access="read", severity="info", signals=[],
    )
    assert "version" not in rec
    assert "classification" not in rec
    assert "decisions" not in rec


def test_v2_record_round_trips_canonical_hash_sign_verify(tmp_path):
    store = RecordStore(str(tmp_path / "rec.jsonl"), signer=_signer())
    rec = store.append(
        server="db", tool="drop_table", args={"name": "orders"},
        access="write", severity="critical", signals=["irreversible:drop"],
        outcome="blocked",
        classification="irreversible",
        decisions=DECISIONS,
    )
    assert rec["version"] == RECORD_VERSION
    assert rec["classification"] == "irreversible"
    assert rec["decisions"] == DECISIONS

    result = verify_records(read_records(str(tmp_path / "rec.jsonl")))
    assert result.issues == []
    if signing.available():
        assert result.ok


def test_v2_still_never_stores_raw_arguments(tmp_path):
    """The v2 fields must not become a side door for secrets."""
    store = RecordStore(str(tmp_path / "rec.jsonl"), signer=_signer())
    store.append(
        server="db", tool="login", args={"password": "hunter2"},
        access="write", severity="high", signals=[],
        classification="sensitive", decisions=DECISIONS,
    )
    text = (tmp_path / "rec.jsonl").read_text()
    assert "hunter2" not in text
    assert "password" not in text


def test_a_mixed_version_chain_verifies(tmp_path):
    """A gateway upgraded mid-session writes both formats into one file."""
    path = tmp_path / "rec.jsonl"
    store = RecordStore(str(path), signer=_signer())
    store.append(server="s", tool="a", args={}, access="read", severity="info", signals=[])
    store.append(
        server="s", tool="b", args={}, access="write", severity="high", signals=[],
        classification="irreversible", decisions=DECISIONS,
    )
    store.append(server="s", tool="c", args={}, access="read", severity="info", signals=[])

    result = verify_records(read_records(str(path)))
    assert result.issues == []
    assert result.total == 3


def test_a_pure_v1_log_written_before_this_change_still_verifies(tmp_path):
    """Fixture-style: a hand-built v1 chain, exactly the old on-disk shape."""
    path = tmp_path / "v1.jsonl"
    store = RecordStore(str(path), signer=_signer())
    for i in range(3):
        store.append(
            server="s", tool=f"t{i}", args={"i": i},
            access="read", severity="info", signals=[],
        )
    records = read_records(str(path))
    assert all("version" not in r for r in records)
    result = verify_records(records)
    assert result.issues == []


def test_tampering_with_a_decision_is_detected(tmp_path):
    """The whole point: flipping `deny` to `allow` must break the chain."""
    path = tmp_path / "rec.jsonl"
    store = RecordStore(str(path), signer=_signer())
    store.append(
        server="db", tool="drop_table", args={"name": "orders"},
        access="write", severity="critical", signals=[], outcome="blocked",
        classification="irreversible", decisions=DECISIONS,
    )
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["decisions"][2]["decision"] = "allow"  # rewrite history
    path.write_text(json.dumps(rec) + "\n")

    result = verify_records(read_records(str(path)))
    assert not result.ok
    assert "tamper" in {i["kind"] for i in result.issues}


def test_tampering_with_the_classification_is_detected(tmp_path):
    path = tmp_path / "rec.jsonl"
    store = RecordStore(str(path), signer=_signer())
    store.append(
        server="db", tool="drop_table", args={}, access="write",
        severity="critical", signals=[],
        classification="irreversible", decisions=DECISIONS,
    )
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["classification"] = "read"  # downgrade the risk after the fact
    path.write_text(json.dumps(rec) + "\n")

    result = verify_records(read_records(str(path)))
    assert not result.ok
    assert "tamper" in {i["kind"] for i in result.issues}


def test_stripping_the_version_field_cannot_downgrade_a_v2_record(tmp_path):
    """Removing `version` must not make verify re-read a v2 payload as v1.

    If it did, an attacker could drop `version`, `classification` and
    `decisions` together and produce a record that verifies as a clean v1 call
    — deleting the evidence of a denial while keeping the chain intact.
    """
    path = tmp_path / "rec.jsonl"
    store = RecordStore(str(path), signer=_signer())
    store.append(
        server="db", tool="drop_table", args={}, access="write",
        severity="critical", signals=[], outcome="blocked",
        classification="irreversible", decisions=DECISIONS,
    )
    rec = json.loads(path.read_text().splitlines()[0])
    for gone in ("version", "classification", "decisions"):
        rec.pop(gone)
    path.write_text(json.dumps(rec) + "\n")

    result = verify_records(read_records(str(path)))
    assert not result.ok
    assert {i["kind"] for i in result.issues} & {"tamper", "malformed"}


def test_adding_a_version_field_to_a_v1_record_is_detected(tmp_path):
    path = tmp_path / "rec.jsonl"
    store = RecordStore(str(path), signer=_signer())
    store.append(server="s", tool="a", args={}, access="read", severity="info", signals=[])
    rec = json.loads(path.read_text().splitlines()[0])
    rec["version"] = 2
    path.write_text(json.dumps(rec) + "\n")

    result = verify_records(read_records(str(path)))
    assert not result.ok
    assert {i["kind"] for i in result.issues} & {"tamper", "malformed"}


def test_an_unrecognized_future_version_fails_loudly(tmp_path):
    """A v3 record read by a v2 verifier is 'cannot verify', never 'verified'."""
    path = tmp_path / "rec.jsonl"
    store = RecordStore(str(path), signer=_signer())
    store.append(
        server="s", tool="a", args={}, access="read", severity="info", signals=[],
        classification="read", decisions=[],
    )
    rec = json.loads(path.read_text().splitlines()[0])
    rec["version"] = 99
    path.write_text(json.dumps(rec) + "\n")

    result = verify_records(read_records(str(path)))
    assert not result.ok
    assert "unknown_version" in {i["kind"] for i in result.issues}


@pytest.mark.skipif(not signing.available(), reason="cryptography not installed")
def test_v2_signature_covers_the_new_fields(tmp_path):
    """Not just the chain: the Ed25519 signature must fail on a decision edit."""
    path = tmp_path / "rec.jsonl"
    store = RecordStore(str(path), signer=_signer())
    store.append(
        server="db", tool="drop_table", args={}, access="write",
        severity="critical", signals=[],
        classification="irreversible", decisions=DECISIONS,
    )
    rec = json.loads(path.read_text().splitlines()[0])
    rec["decisions"] = []
    # Recompute the chain hash so ONLY the signature can catch this.
    from pramiti_mcp_gateway.records import canonical
    import hashlib

    payload = {k: rec[k] for k in PAYLOAD_FIELDS_V2}
    rec["record_hash"] = hashlib.sha256(canonical(payload)).hexdigest()
    path.write_text(json.dumps(rec) + "\n")

    result = verify_records(read_records(str(path)))
    assert not result.ok
    assert "bad_signature" in {i["kind"] for i in result.issues}
