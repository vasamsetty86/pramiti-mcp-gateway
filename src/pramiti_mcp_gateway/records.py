"""Append-only, hash-chained record of observed MCP tool calls.

Every tool call the passive gateway forwards is written as one JSON line. Each
record's ``record_hash`` is ``sha256`` over its canonical payload — which
includes the previous record's hash — so the file is a tamper-evident chain:
altering, reordering, or deleting any record breaks the linkage of everything
after it. Signing (optional, see ``signing.py``) adds non-repudiation on top.

Raw tool arguments are never stored — only their ``sha256`` — so the evidence
log itself does not become a place secrets leak to.

The chain-and-hash logic is pure stdlib; it does not require ``cryptography``
and never touches the offline ``scan`` path.
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pramiti_mcp_gateway.signing import Signer

# The fields that make up the signed/hashed payload. record_hash, signature,
# and public_key are DERIVED and are NOT part of the payload. This tuple is the
# single source of truth shared with verify.py so verification cannot drift from
# what was hashed.
PAYLOAD_FIELDS = (
    "seq", "ts", "server", "tool", "args_sha256",
    "access", "severity", "signals", "outcome", "prev_hash",
)


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
        """Continue an existing chain, or start a new one (seq 0, prev '')."""
        if not self.path.exists():
            return 0, ""
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return 0, ""
        rec = json.loads(last)
        return int(rec["seq"]) + 1, rec["record_hash"]

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
    ) -> dict:
        """Record one observed tool call and return the written record."""
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
