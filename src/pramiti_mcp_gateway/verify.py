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

import hashlib
from dataclasses import dataclass, field

from pramiti_mcp_gateway import signing
from pramiti_mcp_gateway.records import (
    PAYLOAD_FIELDS,
    PAYLOAD_FIELDS_V2,
    RECORD_VERSION,
    canonical,
)

# Keys that are legitimately OUTSIDE the hashed payload because they are derived
# from it. Anything else in a record is unauthenticated data, and unauthenticated
# data that a reader renders is a forgery surface.
DERIVED_FIELDS = ("record_hash", "signature", "public_key")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _payload_fields_for(rec: dict):
    """Which field tuple this record was hashed over. None if unrecognized.

    Dispatch is on the record's own `version`, which is itself inside the v2
    payload — so the discriminator cannot be edited without breaking the hash.
    Stripping `version` from a v2 record makes this read it as v1 and recompute
    over the wrong, smaller field set, which surfaces as `tamper`. That is the
    intended outcome: the alternative would let an attacker delete the decision
    record and still verify clean.

    An unrecognized version is an error, never a fallback. A verifier that
    silently treats a future format as v1 would report "verified" for a payload
    it did not actually check — the same "could not verify is never verified"
    rule this module already applies to signatures.
    """
    version = rec.get("version")
    if version is None:
        return PAYLOAD_FIELDS
    if version == RECORD_VERSION:
        return PAYLOAD_FIELDS_V2
    return None


@dataclass
class VerifyResult:
    total: int = 0
    signed: int = 0
    unsigned: int = 0
    issues: list = field(default_factory=list)  # {seq, kind, detail} — fatal
    # Facts a reader needs that are not, by themselves, verification failures.
    # `unpinned_key` lives here: a chain signed by a key carried inside its own
    # records is internally consistent and might still be someone else's, but
    # making that fatal would fail every log written before pinning existed.
    advisories: list = field(default_factory=list)

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
            "advisories": list(self.advisories),
        }


def verify_records(records: list, expected_public_key: str = None) -> VerifyResult:
    """Verify a chain. Pass *expected_public_key* to PIN it to a known signer.

    Without pinning, each record is checked against the public key stored inside
    that same record — which proves the record was signed by whoever wrote it,
    and nothing more. An attacker who generates their own keypair can produce a
    wholly fabricated log that verifies clean. That is not a flaw in Ed25519; it
    is what "no trusted key" means, and the honest report for it is
    `unpinned_key`, not silence.

    `pramiti-mcp-verify` already models this correctly for SEP records; this
    brings the gateway verifier to the same standard.
    """
    result = VerifyResult(total=len(records))
    prev_hash = ""
    crypto_ok = signing.available()
    expected_public_key = (expected_public_key or "").strip().lower() or None
    seen_keys: set = set()

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
        fields = _payload_fields_for(rec)
        if fields is None:
            result.issues.append(
                {"seq": seq, "kind": "unknown_version",
                 "detail": f"record format version {rec.get('version')!r} is newer "
                           f"than this verifier understands (supports v1 and "
                           f"v{RECORD_VERSION}) — cannot verify"}
            )
            # Still account for it, or signed + unsigned stops equalling total
            # and a reader cannot tell whether a record was skipped or missed.
            if rec.get("signature") and rec.get("public_key"):
                result.signed += 1
            else:
                result.unsigned += 1
            prev_hash = rec.get("record_hash", "")
            continue
        try:
            payload = {k: rec[k] for k in fields}
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

        # Fields OUTSIDE the authenticated set are the forgery surface the hash
        # cannot see. A v1 record (no `version`) is hashed over the 10 v1 fields,
        # so appending `classification` and `decisions` to it leaves the hash and
        # the signature valid — while `agentguard log` happily renders
        # "guard=allow(approved by security@corp)" for a call nobody approved.
        # Rejecting unknown keys closes the whole class rather than this instance.
        unauthenticated = sorted(
            set(rec) - set(fields) - set(DERIVED_FIELDS)
        )
        if unauthenticated:
            result.issues.append(
                {"seq": seq, "kind": "unauthenticated_fields",
                 "detail": f"record carries field(s) {unauthenticated} that are "
                           f"outside the signed payload for its format version"}
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
        elif expected_public_key and str(pub).strip().lower() != expected_public_key:
            result.signed += 1
            result.issues.append(
                {"seq": seq, "kind": "wrong_key",
                 "detail": f"record is signed by {str(pub)[:16]}..., not the "
                           f"pinned key {expected_public_key[:16]}..."}
            )
        elif not signing.verify_signature(pub, stored or expected, sig):
            result.signed += 1
            result.issues.append(
                {"seq": seq, "kind": "bad_signature",
                 "detail": "Ed25519 signature does not verify against public_key"}
            )
        else:
            result.signed += 1
            seen_keys.add(str(pub).strip().lower())

        prev_hash = stored or expected

    if seen_keys and expected_public_key is None:
        # Advisory, never fatal: a log can be internally consistent and still be
        # someone else's. Saying so is the difference between "verified" and
        # "verified against a key you never chose to trust" — but making it fail
        # would break every log written before pinning existed.
        result.advisories.append(
            {"seq": None, "kind": "unpinned_key",
             "detail": "signatures verify against keys carried IN the records "
                       f"({', '.join(sorted(k[:16] + '...' for k in seen_keys))}). "
                       "Re-run with the expected public key to pin them."}
        )
    if len(seen_keys) > 1:
        # Could be legitimate key rotation, could be a spliced chain. Surface it
        # and let the reader decide.
        result.advisories.append(
            {"seq": None, "kind": "mixed_keys",
             "detail": f"records in one chain are signed by {len(seen_keys)} "
                       "different keys"}
        )

    return result
