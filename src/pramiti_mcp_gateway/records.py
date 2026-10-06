"""Append-only, hash-chained record of observed MCP tool calls.

Every tool call the passive gateway forwards is written as one JSON line. Each
record's ``record_hash`` is ``sha256`` over its canonical payload — which
includes the previous record's hash — so the file is a tamper-evident chain:
altering, reordering, or deleting a record breaks the linkage of everything
after it.

One thing a hash chain cannot prove is its own LENGTH: deleting records from the
END leaves a shorter chain that is still internally consistent. Detecting that
needs a witness kept outside the chain. After every append this store writes
``{seq, record_hash}`` to ``chain_tips.json`` beside the log (the same shape
AgentGuard uses); ``pramiti-mcp-gateway verify`` reports ``truncated`` when the
log is shorter than that witness.

Residual, stated plainly: someone who deletes BOTH the log and its witness
leaves no evidence of either. This raises truncation from "undetectable" to
"requires deleting a second file", which is the honest limit of a local,
single-writer design. Signing (optional, see ``signing.py``) adds
non-repudiation on top.

Resuming over an existing file re-verifies the WHOLE chain first (RR-289):
linkage, sequence density, and hash recompute of every record. A truncated-
mid-record or tail-edited file raises ``TamperedChainError`` instead of
silently becoming the new chain tip — a tampered chain must not keep growing.
The resume walk checks hashes, not signatures (signatures stay optional and
are the offline ``verify`` command's job). Resume does not consult the
witness: a whole-record end-truncation is still internally consistent, and
continuing it would overwrite the tip. ``verify`` is the length check.

Raw tool arguments are never stored — only their ``sha256`` — so the evidence
log itself does not become a place secrets leak to.

The chain-and-hash logic is pure stdlib; it does not require ``cryptography``
and never touches the offline ``scan`` path.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pramiti_mcp_gateway.signing import Signer

logger = logging.getLogger("pramiti_mcp_gateway.records")

# A hash chain proves nothing about its own LENGTH. After every append we
# record the highest (seq, record_hash) seen for that file. `verify`
# cross-checks it and reports `truncated` when the log is shorter.
TIPS_FILENAME = "chain_tips.json"

# The fields that make up the signed/hashed payload. record_hash, signature,
# and public_key are DERIVED and are NOT part of the payload. This tuple is the
# single source of truth shared with verify.py so verification cannot drift from
# what was hashed.
PAYLOAD_FIELDS = (
    "seq", "ts", "server", "tool", "args_sha256",
    "access", "severity", "signals", "outcome", "prev_hash",
)

# v2 adds what an ACTIVE gateway DECIDED, on top of what v1 OBSERVED:
#   classification — the risk tier the decision was taken against
#   decisions      — [{policy, decision, reason}, ...] in pipeline order
#   version        — the discriminator verify.py dispatches on
#
# These belong INSIDE the signed payload. An "approved" the hash chain does not
# cover is not evidence; it is a line of text anyone can edit.
#
# A strict extension of PAYLOAD_FIELDS: a v1 record is exactly a v2 record minus
# the three new fields, so both verification paths share one implementation.
PAYLOAD_FIELDS_V2 = PAYLOAD_FIELDS + ("classification", "decisions", "version")

# Stamped into every v2 record. A record with no `version` key is v1 — the
# format that existed before decisions were recorded.
RECORD_VERSION = 2


class TamperedChainError(RuntimeError):
    """Resume refused: the existing records file fails chain verification.

    Raised by ``RecordStore`` when opening a JSONL file whose chain is
    inconsistent (broken linkage, non-dense sequence, hash mismatch, or an
    unparseable/unknown-format record). Appending to such a file would
    silently fork the evidence chain past the tamper point, so the store
    fails loudly instead. Recovery is explicit: inspect the file with
    'pramiti-mcp-gateway verify', then move it aside (quarantine) and start
    a fresh chain — never append over it.
    """


def canonical(payload: dict) -> bytes:
    """Deterministic serialization used for hashing and signing."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_args(args) -> str:
    """sha256 of canonical arguments. Raw args are never persisted."""
    if args is None:
        args = {}
    return _sha256_hex(canonical(args) if isinstance(args, dict) else json.dumps(args).encode())


def _tips_path_for(log_path: Path) -> Path:
    return Path(log_path).parent / TIPS_FILENAME


def read_tips_file(tips_path: Path) -> dict:
    if not tips_path.exists():
        return {}
    try:
        data = json.loads(tips_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


@contextmanager
def _tips_lock(tips_path: Path):
    """Exclusive lock over the shared witness file.

    Several gateway processes (or AgentGuard sessions composing this store)
    can share one directory and therefore one ``chain_tips.json``. Without a
    lock the read-modify-write races and a truncated log verifies clean
    against a stale tip. POSIX only, matching AgentGuard.
    """
    lock_path = tips_path.with_suffix(".lock")
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(lock_path, "a+")
    except OSError:  # pragma: no cover - unwritable log dir
        yield None
        return
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield handle
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def write_chain_tip(log_path: Path, record: dict) -> None:
    """Witness the chain's high-water mark. Never fatal if it fails.

    A witness that could take down the gateway would be a worse trade than
    the truncation it detects, so a write failure is logged and the call
    proceeds — the record itself is already safely appended.
    """
    tips_path = _tips_path_for(log_path)
    try:
        with _tips_lock(tips_path):
            tips = read_tips_file(tips_path)
            name = Path(log_path).name
            previous = tips.get(name, {})
            if int(record["seq"]) >= int(previous.get("seq", -1)):
                tips[name] = {
                    "seq": int(record["seq"]),
                    "record_hash": record["record_hash"],
                }
                tmp = tips_path.with_suffix(f".{os.getpid()}.tmp")
                tmp.write_text(json.dumps(tips), encoding="utf-8")
                os.replace(tmp, tips_path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not update the chain-tip witness: %s", exc)


def load_tips_beside(log_path: Path):
    """Load ``chain_tips.json`` beside the log, or None if missing/unreadable.

    None (no usable witness) is distinct from ``{}`` (readable file, no
    entries): verify advisories ``no_witness`` only in the first case, and
    when the file has no entry for this log name.
    """
    tips_path = _tips_path_for(Path(log_path))
    if not tips_path.exists():
        return None
    try:
        loaded = json.loads(tips_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("could not read the chain-tip witness: %s", exc)
        return None
    return loaded if isinstance(loaded, dict) else None


def chain_tip_issues(records: list, tip) -> list:
    """Issues for a log shorter than, or disagreeing with, its recorded tip."""
    if not isinstance(tip, dict) or "seq" not in tip:
        return []
    issues = []
    highest = int(records[-1]["seq"]) if records else -1
    if highest < int(tip["seq"]):
        issues.append({
            "seq": highest,
            "kind": "truncated",
            "detail": (
                f"the chain ends at seq {highest} but {int(tip['seq'])} records "
                f"were written — {int(tip['seq']) - highest} have been removed "
                f"from the end"
            ),
        })
    elif highest == int(tip["seq"]) and records:
        stored = records[-1].get("record_hash")
        if stored != tip.get("record_hash"):
            issues.append({
                "seq": highest,
                "kind": "tip_mismatch",
                "detail": "the final record differs from the recorded chain tip",
            })
    return issues


class RecordStore:
    """Appends signed, hash-chained records to a JSONL file.

    Single-writer by design (one gateway process per file). Appends are
    serialized with a lock for thread safety within that process.
    """

    def __init__(self, path: str, signer: Optional[Signer] = None):
        self.path = Path(path)
        self.signer = signer
        self._lock = threading.Lock()
        self._seq, self._prev_hash = self._resume()

    def _resume(self) -> tuple[int, str]:
        """Continue an existing chain, or start a new one (seq 0, prev '').

        RR-289: the WHOLE existing chain is verified before its last record is
        adopted as the tip — trusting the last line alone would let a
        truncated or tail-replaced file silently fork the chain at the next
        append. These are local JSONL files, so a full walk is cheap; any
        inconsistency raises ``TamperedChainError`` (fail loud, refuse to
        append). Hash/linkage only — signature verification stays in
        ``verify.py`` where the optional ``cryptography`` dependency lives.
        """
        if not self.path.exists():
            return 0, ""
        seq = 0
        prev_hash = ""
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                prev_hash = self._verify_resume_record(line, lineno, seq, prev_hash)
                seq += 1
        return seq, prev_hash

    def _verify_resume_record(
        self, line: str, lineno: int, expected_seq: int, prev_hash: str
    ) -> str:
        """Verify one record during resume; return its hash as the new tip."""

        def refuse(detail: str) -> TamperedChainError:
            return TamperedChainError(
                f"refusing to append to {self.path}: line {lineno} {detail}. "
                "The existing chain does not verify, so continuing it would "
                "silently grow a tampered evidence log. Inspect it with "
                "'pramiti-mcp-gateway verify', then move the file aside "
                "(quarantine) and start a fresh chain."
            )

        try:
            rec = json.loads(line)
        except ValueError:
            raise refuse("is not valid JSON (truncated or corrupted record)") from None
        if not isinstance(rec, dict):
            raise refuse("is not a record object")
        version = rec.get("version")
        if version is None:
            fields = PAYLOAD_FIELDS
        elif version == RECORD_VERSION:
            fields = PAYLOAD_FIELDS_V2
        else:
            raise refuse(
                f"has record format version {version!r}, which this writer "
                "does not understand and therefore cannot verify"
            )
        if rec.get("seq") != expected_seq:
            raise refuse(f"has seq {rec.get('seq')!r}, expected {expected_seq}")
        if rec.get("prev_hash", "") != prev_hash:
            raise refuse("does not link to the preceding record (prev_hash mismatch)")
        try:
            payload = {k: rec[k] for k in fields}
        except KeyError as exc:
            raise refuse(f"is missing payload field {exc}") from None
        record_hash = rec.get("record_hash")
        if record_hash != _sha256_hex(canonical(payload)):
            raise refuse("record_hash does not match its recomputed payload hash")
        # Same rule as verify.py: fields outside the hashed payload (and its
        # derived record_hash/signature/public_key) are unauthenticated data
        # a reader might render — a forgery surface, so a tamper here too.
        unauthenticated = sorted(
            set(rec) - set(fields) - {"record_hash", "signature", "public_key"}
        )
        if unauthenticated:
            raise refuse(
                f"carries field(s) {unauthenticated} outside the signed "
                "payload for its format version"
            )
        return record_hash

    def append(
        self,
        *,
        server: str,
        tool: str,
        args,
        access: str,
        severity: str,
        signals: list,
        outcome: str = "forwarded",
        classification: Optional[str] = None,
        decisions: Optional[list] = None,
    ) -> dict:
        """Record one observed tool call and return the written record.

        Passing ``classification`` or ``decisions`` writes a v2 record; omitting
        both writes a v1 record byte-for-byte identical to what the passive
        gateway has always produced. The caller does not choose a version — the
        presence of decision data determines it, so a passive relay cannot
        accidentally emit v2 records with empty decision fields.
        """
        is_v2 = classification is not None or decisions is not None
        with self._lock:
            payload = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "server": server,
                "tool": tool,
                "args_sha256": hash_args(args),
                "access": access,
                "severity": severity,
                "signals": list(signals),
                "outcome": outcome,
                "prev_hash": self._prev_hash,
            }
            if is_v2:
                payload["classification"] = classification
                payload["decisions"] = list(decisions or [])
                payload["version"] = RECORD_VERSION
            record_hash = _sha256_hex(canonical(payload))
            record = dict(payload)
            record["record_hash"] = record_hash
            if self.signer is not None:
                record["signature"] = self.signer.sign(record_hash)
                record["public_key"] = self.signer.public_hex
            else:
                record["signature"] = None
                record["public_key"] = None

            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")

            write_chain_tip(self.path, record)
            self._seq += 1
            self._prev_hash = record_hash
            return record


def read_records(path: str) -> list[dict]:
    """Load all records from a JSONL file, in order."""
    p = Path(path)
    out: list[dict] = []
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out
