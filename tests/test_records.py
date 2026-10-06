"""Tests for the signed, hash-chained record store and offline verification."""
from __future__ import annotations

import json

import pytest

from pramiti_mcp_gateway import signing
from pramiti_mcp_gateway.records import RecordStore, TamperedChainError, read_records
from pramiti_mcp_gateway.verify import verify_records


def _store(tmp_path, signed=True):
    signer = signing.Signer.generate() if (signed and signing.available()) else None
    return RecordStore(str(tmp_path / "rec.jsonl"), signer=signer), signer


def test_append_builds_a_chain(tmp_path):
    store, _ = _store(tmp_path)
    a = store.append(server="s", tool="delete_x", args={"id": 1},
                     access="write", severity="high", signals=["mutating:delete"])
    b = store.append(server="s", tool="get_x", args={"id": 2},
                     access="read", severity="info", signals=[])
    assert a["seq"] == 0 and a["prev_hash"] == ""
    assert b["seq"] == 1 and b["prev_hash"] == a["record_hash"]
    # raw args are never stored — only their hash.
    text = (tmp_path / "rec.jsonl").read_text()
    assert '"id"' not in text
    assert a["args_sha256"] != b["args_sha256"]


def test_resume_continues_chain(tmp_path):
    store1, signer = _store(tmp_path)
    r0 = store1.append(server="s", tool="a", args={}, access="read", severity="info", signals=[])
    # New store object over the same file must continue, not restart.
    store2 = RecordStore(str(tmp_path / "rec.jsonl"), signer=signer)
    r1 = store2.append(server="s", tool="b", args={}, access="read", severity="info", signals=[])
    assert r1["seq"] == 1
    assert r1["prev_hash"] == r0["record_hash"]


@pytest.mark.skipif(not signing.available(), reason="cryptography not installed")
def test_signed_chain_verifies(tmp_path):
    store, _ = _store(tmp_path, signed=True)
    for i in range(5):
        store.append(server="s", tool=f"t{i}", args={"i": i},
                     access="write", severity="medium", signals=["mutating:set"])
    result = verify_records(read_records(str(tmp_path / "rec.jsonl")))
    assert result.ok
    assert result.signed == 5 and result.unsigned == 0
    assert result.issues == []


def test_unsigned_chain_is_intact_but_not_ok(tmp_path):
    store = RecordStore(str(tmp_path / "rec.jsonl"), signer=None)
    store.append(server="s", tool="a", args={}, access="read", severity="info", signals=[])
    result = verify_records(read_records(str(tmp_path / "rec.jsonl")))
    # Chain is intact (no issues) but unsigned records don't pass the ok gate.
    assert result.issues == []
    assert result.unsigned == 1
    assert result.ok is False


def test_tampered_record_is_detected(tmp_path):
    store, _ = _store(tmp_path)
    store.append(server="s", tool="delete_x", args={"id": 1},
                 access="write", severity="high", signals=["mutating:delete"])
    store.append(server="s", tool="get_x", args={"id": 2},
                 access="read", severity="info", signals=[])
    # Flip a recorded severity on disk — chain hash must no longer match.
    path = tmp_path / "rec.jsonl"
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["severity"] = "info"  # attacker downgrades a critical action
    lines[0] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")

    result = verify_records(read_records(str(path)))
    assert not result.ok
    kinds = {i["kind"] for i in result.issues}
    assert "tamper" in kinds


# --- RR-289: resume must verify the chain, not trust the last line ---------


def _three_record_chain(tmp_path, signed=False):
    store, signer = _store(tmp_path, signed=signed)
    for i in range(3):
        store.append(server="s", tool=f"t{i}", args={"i": i},
                     access="read", severity="info", signals=[])
    return tmp_path / "rec.jsonl", signer


def test_resume_refuses_tail_edited_record(tmp_path):
    """An attacker rewrites the last record (without recomputing its hash);
    a new store over the file must refuse, not adopt it as the chain tip."""
    path, signer = _three_record_chain(tmp_path)
    lines = path.read_text().splitlines()
    rec = json.loads(lines[-1])
    rec["severity"] = "critical"
    lines[-1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(TamperedChainError, match="record_hash does not match"):
        RecordStore(str(path), signer=signer)


def test_resume_refuses_truncated_partial_line(tmp_path):
    """A file truncated mid-record (torn write, tail chop) must refuse."""
    path, signer = _three_record_chain(tmp_path)
    text = path.read_text()
    path.write_text(text[: len(text) - 40])  # tear the last record
    with pytest.raises(TamperedChainError, match="not valid JSON"):
        RecordStore(str(path), signer=signer)


def test_resume_refuses_excised_middle_record(tmp_path):
    """Deleting a middle record breaks seq/linkage — resume must refuse."""
    path, signer = _three_record_chain(tmp_path)
    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(TamperedChainError, match="seq"):
        RecordStore(str(path), signer=signer)


def test_resume_refuses_swapped_in_foreign_tail(tmp_path):
    """A self-consistent record from ANOTHER chain spliced onto the tail has
    the wrong prev_hash — resume must refuse."""
    path, signer = _three_record_chain(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    other_path, _ = _three_record_chain(other)
    lines = path.read_text().splitlines()
    foreign = json.loads(other_path.read_text().splitlines()[0])
    # Give it the right seq so only the linkage (prev_hash) is wrong.
    assert foreign["seq"] == 0
    foreign_line = json.dumps({**foreign, "seq": 3})
    path.write_text("\n".join(lines + [foreign_line]) + "\n")
    with pytest.raises(TamperedChainError):
        RecordStore(str(path), signer=signer)


def test_resume_refuses_unauthenticated_extra_field(tmp_path):
    """A field appended OUTSIDE the hashed payload (e.g. a forged 'decisions'
    on a v1 record) leaves the hash valid but is a forgery surface — refuse."""
    path, signer = _three_record_chain(tmp_path)
    lines = path.read_text().splitlines()
    rec = json.loads(lines[-1])
    rec["decisions"] = [{"policy": "forged", "decision": "allow"}]
    lines[-1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(TamperedChainError, match="outside the signed payload"):
        RecordStore(str(path), signer=signer)


def test_proxy_cli_refuses_tampered_records_file(tmp_path, capsys):
    """The proxy command must exit 1 with a clear message — not a traceback,
    and never a silently forked chain — when its records file is tampered."""
    from pramiti_mcp_gateway.cli import main

    path, _ = _three_record_chain(tmp_path)
    lines = path.read_text().splitlines()
    rec = json.loads(lines[-1])
    rec["outcome"] = "forged"
    lines[-1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    rc = main(["proxy", "--records", str(path), "--", "true"])
    assert rc == 1
    assert "refusing to append" in capsys.readouterr().err


def test_resume_accepts_intact_chain_and_continues(tmp_path):
    """The verification walk must not reject a legitimate chain."""
    path, signer = _three_record_chain(tmp_path)
    store = RecordStore(str(path), signer=signer)
    rec = store.append(server="s", tool="t3", args={}, access="read",
                       severity="info", signals=[])
    assert rec["seq"] == 3
    assert verify_records(read_records(str(path))).issues == []


def test_deleted_record_breaks_chain(tmp_path):
    store, _ = _store(tmp_path)
    for i in range(3):
        store.append(server="s", tool=f"t{i}", args={}, access="read", severity="info", signals=[])
    path = tmp_path / "rec.jsonl"
    lines = path.read_text().splitlines()
    del lines[1]  # excise the middle record
    path.write_text("\n".join(lines) + "\n")
    result = verify_records(read_records(str(path)))
    assert not result.ok
    kinds = {i["kind"] for i in result.issues}
    assert "chain_break" in kinds or "sequence" in kinds
