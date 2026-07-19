"""Ed25519 signing for gateway records.

Optional: signing needs the ``cryptography`` library (the ``sign`` extra). The
hash chain in ``records.py`` is pure stdlib and tamper-evident on its own;
signatures add non-repudiation (proof of *who* recorded a call). When
``cryptography`` is absent, records are hash-chained but unsigned, and
``verify`` flags them as such — the same honest posture as a flight recorder
with no key configured.

Keys are raw 32-byte Ed25519 keys, stored/loaded as hex.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

_CRYPTO_MISSING = (
    "signing needs the 'cryptography' library. Install it with:\n"
    "    pip install 'pramiti-mcp-gateway[sign]'\n"
    "or run unsigned (records stay hash-chained and tamper-evident)."
)

DEFAULT_KEY_PATH = Path.home() / ".config" / "pramiti-mcp-gateway" / "signing.key"
ENV_KEY = "PRAMITI_GATEWAY_KEY"


def available() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def _ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        return ed25519
    except ImportError as exc:  # pragma: no cover - env dependent
        raise RuntimeError(_CRYPTO_MISSING) from exc


class Signer:
    """Signs a record's hex digest with an Ed25519 private key."""

    def __init__(self, private_key):
        self._priv = private_key
        self.public_hex = private_key.public_key().public_bytes_raw().hex()

    def sign(self, hex_digest: str) -> str:
        return self._priv.sign(bytes.fromhex(hex_digest)).hex()

    def private_hex(self) -> str:
        return self._priv.private_bytes_raw().hex()

    @classmethod
    def generate(cls) -> "Signer":
        ed = _ed25519()
        return cls(ed.Ed25519PrivateKey.generate())

    @classmethod
    def from_hex(cls, private_hex: str) -> "Signer":
        ed = _ed25519()
        return cls(ed.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex.strip())))


def verify_signature(public_hex: str, hex_digest: str, signature_hex: str) -> bool:
    """True if *signature_hex* is a valid Ed25519 signature over the digest."""
    ed = _ed25519()
    try:
        pub = ed.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        pub.verify(bytes.fromhex(signature_hex), bytes.fromhex(hex_digest))
        return True
    except Exception:  # noqa: BLE001 - any failure is a non-verifying signature
        return False


def load_signer(key_path: Optional[str] = None) -> tuple[Optional[Signer], str]:
    """Resolve a signer. Returns (signer_or_None, source_note).

    Order: explicit ``key_path`` → ``$PRAMITI_GATEWAY_KEY`` → default key file.
    If none exist and ``cryptography`` is available, returns (None, "unsigned")
    so the caller can decide whether to generate one. If ``cryptography`` is
    missing, returns (None, "no-crypto").
    """
    if not available():
        return None, "no-crypto"
    if key_path:
        return Signer.from_hex(Path(key_path).read_text()), f"key-file:{key_path}"
    env = os.environ.get(ENV_KEY)
    if env:
        return Signer.from_hex(env), "env"
    if DEFAULT_KEY_PATH.exists():
        return Signer.from_hex(DEFAULT_KEY_PATH.read_text()), f"key-file:{DEFAULT_KEY_PATH}"
    return None, "unsigned"


def write_keypair(path: Optional[str] = None) -> tuple[str, str]:
    """Generate and persist a new signing key. Returns (path, public_hex)."""
    signer = Signer.generate()
    dest = Path(path) if path else DEFAULT_KEY_PATH
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(signer.private_hex())
    try:
        dest.chmod(0o600)
    except OSError:  # pragma: no cover - platform dependent
        pass
    return str(dest), signer.public_hex
