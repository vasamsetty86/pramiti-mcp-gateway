"""`pramiti-mcp-gateway verify` must not bless a log it cannot attribute.

Ship-surface seventh pass, finding 7-2 — which is the ORIGINAL Finding 11, fixed
in `agentguard verify` and never here. The library already computed the
`unpinned_key` and `mixed_keys` advisories; `--json` carried them and the text
renderer dropped both, so a chain signed with a key generated ten seconds
earlier printed

    OK — chain intact and every record verified.

and exited 0. There was no `--pubkey` flag at all, so there was no way to ask the
question properly. The README sells this command as the thing "anyone can
[use to] confirm the log wasn't altered".

This is the same rule as everywhere else in this package pair: never report a
clean result for something you could not actually check.
"""
from __future__ import annotations

import pytest
from pramiti_mcp_gateway import signing
from pramiti_mcp_gateway.cli import main
from pramiti_mcp_gateway.records import RecordStore


def _signed_log(path, signer, count=2):
    store = RecordStore(str(path), signer=signer)
    for i in range(count):
        store.append(server="s", tool=f"t{i}", access="read", severity="low",
                     outcome="forwarded", args={}, signals=[])
    return path


@pytest.fixture
def forged(tmp_path):
    """A log built from scratch by an attacker's own freshly generated key."""
    if not signing.available():
        pytest.skip("cryptography not installed")
    attacker = signing.Signer.generate()
    return _signed_log(tmp_path / "forged.jsonl", attacker), attacker


def test_a_fabricated_log_is_not_an_unqualified_pass(forged, capsys):
    path, _attacker = forged
    code = main(["verify", str(path)])
    out = capsys.readouterr().out

    assert code == 3, f"a fabricated log exited {code}; CI reads that as success"
    assert "UNPINNED" in out and "fabricated" in out, out
    assert "OK — chain intact and every record verified." not in out


def test_the_unpinned_advisory_reaches_the_terminal_not_just_json(forged, capsys):
    """The library computed it all along; only the text renderer dropped it."""
    path, _ = forged
    main(["verify", str(path)])
    assert "unpinned_key" in capsys.readouterr().out


def test_pinning_the_wrong_key_fails_outright(forged, capsys):
    path, _attacker = forged
    stranger = signing.Signer.generate()
    assert main(["verify", str(path), "--pubkey", stranger.public_hex]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_pinning_the_right_key_is_a_real_pass(forged, capsys):
    path, attacker = forged
    assert main(["verify", str(path), "--pubkey", attacker.public_hex]) == 0
    assert "pinned key" in capsys.readouterr().out


def test_a_pubkey_may_be_given_as_a_file(forged, tmp_path, capsys):
    path, attacker = forged
    keyfile = tmp_path / "trusted.pub"
    keyfile.write_text(attacker.public_hex + "\n")
    assert main(["verify", str(path), "--pubkey", str(keyfile)]) == 0


def test_allow_unpinned_is_an_explicit_opt_in(forged):
    path, _ = forged
    assert main(["verify", str(path), "--allow-unpinned"]) == 0


def test_a_tampered_chain_still_fails_outright(forged, capsys):
    """Exit 1 must stay reserved for "not trustworthy", distinct from 3."""
    import json

    path, attacker = forged
    lines = path.read_text().splitlines()
    record = json.loads(lines[0])
    record["tool"] = "something_else"
    lines[0] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n")

    assert main(["verify", str(path), "--pubkey", attacker.public_hex]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_verify_discloses_that_it_cannot_detect_truncation(forged, capsys):
    """K-2 (F-306): rewritten, not deleted.

    This pin used to assert a `no_witness` advisory because the gateway CLI
    disclosed that it could not detect tail deletion rather than detecting it
    (ship-surface 8-5). A hash chain still cannot prove its own length; the
    chain-tip witness is the length check. `pramiti-mcp-gateway verify` now
    reports `truncated` when the log is shorter than that witness, matching
    `agentguard verify`. The `no_witness` advisory remains only for logs that
    have no tip file (pre-witness chains, or a deleted witness).
    """
    path, attacker = forged
    path.write_text(path.read_text().splitlines()[0] + "\n")   # drop the tail

    code = main(["verify", str(path), "--pubkey", attacker.public_hex])
    out = capsys.readouterr().out

    assert code == 1, f"a tail-truncated log exited {code}; that is a silent pass"
    assert "truncated" in out, out
    assert "no_witness" not in out, out
