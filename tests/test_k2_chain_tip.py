"""K-2 (F-306): gateway records get a chain-tip witness; verify detects truncation.

A hash chain cannot prove its own LENGTH. Deleting records from the END leaves
a dense, correctly-linked, correctly-signed prefix, so `verify` used to print
OK (and, after a later honesty pass, a `no_witness` advisory) over a shortened
log. AgentGuard already writes `{seq, record_hash}` to `chain_tips.json` after
every append and reports `truncated` when the log is shorter than the witness.
The gateway RecordStore and `pramiti-mcp-gateway verify` must do the same.
"""
from __future__ import annotations

import json

import pytest
from pramiti_mcp_gateway import signing
from pramiti_mcp_gateway.cli import main
from pramiti_mcp_gateway.records import RecordStore


def _append_n(path, signer, n):
    store = RecordStore(str(path), signer=signer)
    last = None
    for i in range(n):
        last = store.append(
            server="s",
            tool=f"t{i}",
            args={"i": i},
            access="read",
            severity="info",
            signals=[],
        )
    return last


def test_append_writes_a_chain_tip_witness(tmp_path):
    path = tmp_path / "rec.jsonl"
    rec = _append_n(path, signer=None, n=1)
    tips_path = tmp_path / "chain_tips.json"
    assert tips_path.exists(), (
        "K-2 (F-306): RecordStore.append must write a chain-tip witness beside "
        "the log so verify can detect records deleted from the end"
    )
    tips = json.loads(tips_path.read_text(encoding="utf-8"))
    assert tips["rec.jsonl"]["seq"] == rec["seq"]
    assert tips["rec.jsonl"]["record_hash"] == rec["record_hash"]


@pytest.mark.skipif(not signing.available(), reason="cryptography not installed")
def test_deleting_the_last_log_line_makes_verify_report_truncated(tmp_path, capsys):
    signer = signing.Signer.generate()
    path = tmp_path / "rec.jsonl"
    _append_n(path, signer=signer, n=3)

    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n", encoding="utf-8")

    code = main(["verify", str(path), "--pubkey", signer.public_hex, "--json"])
    payload = json.loads(capsys.readouterr().out)
    kinds = {i["kind"] for i in payload["issues"]}
    assert code == 1, (
        f"K-2 (F-306): a tail-truncated log must fail verify, not exit {code}"
    )
    assert "truncated" in kinds, (
        "K-2 (F-306): verify must report kind=truncated when the log is shorter "
        f"than the chain-tip witness; issues were {payload['issues']}"
    )
    assert payload["ok"] is False
