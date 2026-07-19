"""Verify a gateway record chain offline.

Recomputes every record's hash from its payload, checks the ``prev_hash``
linkage and sequence numbering, and verifies Ed25519 signatures when present.
Pure with respect to the chain (stdlib); signature checks need ``cryptography``
only when records are actually signed.

Fail-loud: a signed record whose key can't be checked counts as a failure, not
a pass ("could not verify" is never "verified"). An unsigned record is reported
as unsigned and does not, by itself, pass the ``ok`` gate.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from pramiti_mcp_gateway.records import PAYLOAD_FIELDS, canonical
from pramiti_mcp_gateway import signing

import hashlib


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class VerifyResult:
    total: int = 0
    signed: int = 0
    unsigned: int = 0
    issues: list = field(default_factory=list)  # {seq, kind, detail}

    @property
    def ok(self) -> bool:
        # Chain must be intact AND every record must carry a valid signature.
        return not self.issues and self.total > 0 and self.unsigned == 0

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "total": self.total,
            "signed": self.signed,
            "unsigned": self.unsigned,
            "issues": list(self.issues),
        }


def verify_records(records: list) -> VerifyResult:
    result = VerifyResult(total=len(records))
    prev_hash = ""
    crypto_ok = signing.available()

    for i, rec in enumerate(records):
        seq = rec.get("seq")

        # 1. sequence numbering must be dense and increasing from 0.
        if seq != i:
            result.issues.append(
                {"seq": seq, "kind": "sequence", "detail": f"expected seq {i}, got {seq}"}
            )

        # 2. chain linkage: this record's prev_hash must equal the prior hash.
        if rec.get("prev_hash", "") != prev_hash:
            result.issues.append(
                {"seq": seq, "kind": "chain_break",
                 "detail": "prev_hash does not match the preceding record"}
            )

        # 3. tamper check: recompute the hash from the payload.
        try:
            payload = {k: rec[k] for k in PAYLOAD_FIELDS}
        except KeyError as exc:
            result.issues.append(
                {"seq": seq, "kind": "malformed", "detail": f"missing field {exc}"}
            )
            prev_hash = rec.get("record_hash", "")
            continue
        expected = _sha256_hex(canonical(payload))
        stored = rec.get("record_hash")
        if stored != expected:
            result.issues.append(
                {"seq": seq, "kind": "tamper",
                 "detail": "record_hash does not match recomputed payload hash"}
            )

        # 4. signature.
        sig = rec.get("signature")
        pub = rec.get("public_key")
        if not sig or not pub:
            result.unsigned += 1
        elif not crypto_ok:
            # A signed record we cannot check is a failure, not a pass.
            result.signed += 1
            result.issues.append(
                {"seq": seq, "kind": "unverifiable",
                 "detail": "record is signed but 'cryptography' is not installed to verify it"}
            )
        elif not signing.verify_signature(pub, stored or expected, sig):
            result.signed += 1
            result.issues.append(
                {"seq": seq, "kind": "bad_signature",
                 "detail": "Ed25519 signature does not verify against public_key"}
            )
        else:
            result.signed += 1

        prev_hash = stored or expected

    return result
