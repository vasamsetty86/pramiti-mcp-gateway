"""Tests for signing-key persistence (A-RD-014: no world-readable window)."""
from __future__ import annotations

import os
import stat

import pytest

from pramiti_mcp_gateway import signing

pytestmark = pytest.mark.skipif(
    not signing.available(), reason="cryptography not installed"
)


@pytest.fixture
def permissive_umask():
    """Run with umask 0o000 — the worst case for chmod-after-write bugs."""
    old = os.umask(0o000)
    try:
        yield
    finally:
        os.umask(old)


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_write_keypair_creates_owner_only_file(tmp_path, permissive_umask):
    """The key file must be 0600 from CREATION, even under umask 0o000 —
    the mode goes to os.open, so there is no window where the private key
    is world-readable on disk."""
    dest = tmp_path / "signing.key"
    path, public_hex = signing.write_keypair(str(dest))
    assert path == str(dest)
    assert _mode(dest) == 0o600
    # Round-trips: the persisted key loads and matches the returned public key.
    assert signing.Signer.from_hex(dest.read_text()).public_hex == public_hex


def test_write_keypair_tightens_a_preexisting_file(tmp_path, permissive_umask):
    """O_CREAT ignores its mode for an existing file — the explicit chmod
    must still bring a loose pre-existing key file down to 0600."""
    dest = tmp_path / "signing.key"
    dest.write_text("stale")
    dest.chmod(0o644)
    signing.write_keypair(str(dest))
    assert _mode(dest) == 0o600


def test_write_keypair_overwrites_content_completely(tmp_path):
    """O_TRUNC: a longer stale file must not leave trailing garbage that
    corrupts the stored hex key."""
    dest = tmp_path / "signing.key"
    dest.write_text("x" * 500)
    _, public_hex = signing.write_keypair(str(dest))
    assert signing.Signer.from_hex(dest.read_text()).public_hex == public_hex
