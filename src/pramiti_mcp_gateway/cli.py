"""pramiti-mcp-gateway — command-line entry point.

Usage:
    pramiti-mcp-gateway scan <manifest.json> [--json] [--fail-on <severity>]

`scan` reads a manifest of MCP tools (a `tools/list` result, a bare list, or a
`{"servers": {...}}` object) and prints a security posture report. Exit code is
0 unless `--fail-on <severity>` is set and a tool at or above that severity is
found (for CI gating).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from pramiti_mcp_gateway import __version__
from pramiti_mcp_gateway.classifier import SEVERITY_ORDER
from pramiti_mcp_gateway.scan import render_text, scan_manifest


def _load(path: str):
    if path == "-":
        return json.loads(sys.stdin.read())
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _cmd_scan(args) -> int:
    if not args.config and not args.manifest:
        print(
            "error: provide a manifest path (or '-'), or use --config to "
            "connect to live servers.",
            file=sys.stderr,
        )
        return 1
    unreachable: dict = {}
    if args.config:
        from pramiti_mcp_gateway.connect import discover, load_config

        try:
            servers = load_config(args.config)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"error: could not read config: {exc}", file=sys.stderr)
            return 1
        try:
            manifest, errors = discover(servers, timeout=args.timeout)
        except RuntimeError as exc:  # mcp SDK not installed
            print(f"error: {exc}", file=sys.stderr)
            return 1
        for name, err in errors.items():
            print(
                f"warning: server '{name}' could not be scanned: {err}",
                file=sys.stderr,
            )
        # These must reach the exit gate below. A server we could not CONNECT to
        # is a server we did not inspect, exactly like one whose manifest entry
        # we could not read — and this is the path the error text for an
        # mcpServers config actively tells users to run. Left out of the gate,
        # `scan --config` with zero servers reachable printed "No high-severity
        # action tools detected" and exited 0: a clean bill of health for a stack
        # never reached.
        unreachable = dict(errors)
    else:
        try:
            manifest = _load(args.manifest)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: could not read manifest: {exc}", file=sys.stderr)
            return 1

    try:
        report = scan_manifest(manifest)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for name, why in unreachable.items():
        report.unreadable.setdefault(name, f"could not connect: {why}")

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_text(report))

    if args.fail_on:
        threshold = SEVERITY_ORDER.index(args.fail_on)
        worst = SEVERITY_ORDER.index(report.max_severity())
        if report.tools and worst >= threshold:
            print(
                f"\nFAIL: found a tool at severity '{report.max_severity()}' "
                f"(>= --fail-on '{args.fail_on}').",
                file=sys.stderr,
            )
            return 2

    # Exit 0 requires that something was actually inspected. "I looked and found
    # nothing" and "I could not look" are different answers and must not share an
    # exit code: a manifest whose servers could none of them be read otherwise
    # produced an empty, reassuring report and exit 0 — a clean bill of health
    # for a stack this scanner never saw. An EMPTY stack is still exit 0; only a
    # failure to read is not.
    if not report.tools and report.unreadable:
        print(
            f"\nNO POSTURE: {len(report.unreadable)} server(s) could not be read "
            f"and no tool was inspected, so this is not a finding of safety — it "
            f"is a failure to look.",
            file=sys.stderr,
        )
        return 1
    return 0


def _cmd_keygen(args) -> int:
    from pramiti_mcp_gateway import signing

    if not signing.available():
        print(f"error: {signing._CRYPTO_MISSING}", file=sys.stderr)
        return 1
    path, public_hex = signing.write_keypair(args.out)
    print(f"wrote signing key: {path}")
    print(f"public key (share with auditors): {public_hex}")
    return 0


def _cmd_proxy(args) -> int:
    import asyncio

    from pramiti_mcp_gateway import signing
    from pramiti_mcp_gateway.records import RecordStore, TamperedChainError

    if args.url:
        spec = {"url": args.url}
    elif args.command:
        cmd = [c for c in args.command if c != "--"]
        if not cmd:
            print("error: no downstream command after '--'.", file=sys.stderr)
            return 1
        spec = {"command": cmd[0], "args": cmd[1:]}
    else:
        print(
            "error: specify the downstream server as '-- <command> [args...]' "
            "or with --url.",
            file=sys.stderr,
        )
        return 1

    signer, source = signing.load_signer(args.key)
    if signer is None:
        # All diagnostics go to STDERR — stdout is the MCP protocol channel.
        if source == "no-crypto":
            print(
                "warning: running UNSIGNED (records stay hash-chained). Install "
                "the 'sign' extra and run keygen for signed evidence.",
                file=sys.stderr,
            )
        else:
            print(
                "warning: no signing key found — running UNSIGNED. Run "
                "'pramiti-mcp-gateway keygen' for signed, non-repudiable records.",
                file=sys.stderr,
            )

    try:
        store = RecordStore(args.records, signer=signer)
    except TamperedChainError as exc:
        # RR-289: never grow a chain that does not verify. The operator must
        # quarantine the file explicitly; there is no append-anyway override.
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"pramiti-mcp-gateway: passive proxy for '{args.server_name}' -> "
        f"records: {args.records} ({'signed' if signer else 'unsigned'})",
        file=sys.stderr,
    )
    try:
        from pramiti_mcp_gateway.proxy import run_proxy
    except ImportError:
        print(
            "error: the proxy needs the MCP SDK. Install with "
            "'pip install pramiti-mcp-gateway[connect]'.",
            file=sys.stderr,
        )
        return 1
    try:
        asyncio.run(run_proxy(spec, args.server_name, store))
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        return 0
    return 0


def _cmd_posture(args) -> int:
    from pramiti_mcp_gateway.posture import render_text, summarize
    from pramiti_mcp_gateway.records import read_records

    try:
        records = read_records(args.records)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not read records: {exc}", file=sys.stderr)
        return 1
    summary = summarize(records)
    print(json.dumps(summary, indent=2) if args.json else render_text(summary))
    return 0


def _add_advisory(result, kind: str, detail: str) -> None:
    """Attach a non-fatal note. Advisories qualify an OK; they do not deny it."""
    notes = getattr(result, "advisories", None)
    if notes is None:
        try:
            result.advisories = []
        except Exception:  # pragma: no cover - frozen result type
            print("advisory dropped: result type is frozen", file=sys.stderr)
            return
        notes = result.advisories
    notes.append({"kind": kind, "detail": detail})


def _cmd_verify(args) -> int:
    from pramiti_mcp_gateway.records import (
        TIPS_FILENAME,
        chain_tip_issues,
        load_tips_beside,
        read_records,
    )
    from pramiti_mcp_gateway.verify import verify_records

    try:
        records = read_records(args.records)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not read records: {exc}", file=sys.stderr)
        return 1
    pinned = getattr(args, "pubkey", None)
    if pinned:
        candidate = Path(pinned).expanduser()
        if candidate.exists():
            pinned = candidate.read_text(encoding="utf-8").strip()

    result = verify_records(records, expected_public_key=pinned)

    # The witness is what makes tail-truncation detectable at all. Its ABSENCE
    # is therefore a fact about how much this verification proves: deleting
    # chain_tips.json restores the truncation bypass, and silence about that
    # would print "OK — chain intact" over a check that did not run.
    log_path = Path(args.records)
    tips = load_tips_beside(log_path)
    if tips is None:
        _add_advisory(
            result,
            "no_witness",
            f"no readable {TIPS_FILENAME} beside this log, so tail-truncation "
            f"could not be checked — records removed from the end would not be "
            f"detected here.",
        )
    elif log_path.name not in tips:
        _add_advisory(
            result,
            "no_witness",
            f"{TIPS_FILENAME} has no entry for {log_path.name}, so "
            f"tail-truncation could not be checked for this log.",
        )
    else:
        result.issues.extend(chain_tip_issues(records, tips.get(log_path.name)))

    advisories = list(getattr(result, "advisories", []))
    unpinned = not pinned and any(n["kind"] == "unpinned_key" for n in advisories)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        r = result
        print(f"records: {r.total}   signed: {r.signed}   unsigned: {r.unsigned}")
        for issue in r.issues:
            print(f"  [{issue['kind']}] seq={issue['seq']}: {issue['detail']}")
        # The text renderer used to DROP the advisories that `verify_records`
        # already computes — `--json` carried them, the terminal did not — so a
        # log signed with a key generated ten seconds earlier printed
        # "OK — chain intact and every record verified." and exited 0. The README
        # sells this command as "anyone can confirm the log wasn't altered", and
        # a forged chain passed it. Same defect agentguard's verify had; it was
        # fixed there and never here.
        for note in advisories:
            print(f"  note: [{note['kind']}] {note['detail']}")
        if r.ok and unpinned:
            print(
                "OK (UNPINNED) — the chain is internally consistent, but the "
                "signatures were checked against a key carried IN the log itself, "
                "so this does NOT establish who produced it. A fabricated log "
                "passes this check.\n"
                "  Re-run with --pubkey <file|hex> to verify against a key you "
                "chose to trust, or --allow-unpinned to accept this as success."
            )
        elif r.ok:
            print("OK — chain intact and every record verified"
                  + (" against the pinned key." if pinned else "."))
        else:
            print("FAIL — see issues above.")

    if not result.ok:
        return 1
    if unpinned and not getattr(args, "allow_unpinned", False):
        # 3 = verified what is present, but nothing pins it to a key you trust.
        # Distinct from 1 so "tampered" and "provenance unknown" stay tellable
        # apart, matching `agentguard verify`.
        return 3
    return 0


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pramiti-mcp-gateway",
        description="Security posture scanner and passive gateway for Model "
        "Context Protocol (MCP) servers.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser(
        "scan",
        help="Classify the action risk of an MCP server's declared tools.",
    )
    p_scan.add_argument(
        "manifest",
        nargs="?",
        help="Path to a JSON tools manifest, or '-' to read from stdin. "
        "Omit when using --config.",
    )
    p_scan.add_argument(
        "--config",
        metavar="FILE",
        help="Connect to the MCP servers in this client config (mcpServers "
        "shape) and scan their live tools. Requires the 'connect' extra "
        "(pip install 'pramiti-mcp-gateway[connect]').",
    )
    p_scan.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Per-server connect/list timeout in seconds (default 30).",
    )
    p_scan.add_argument(
        "--json", action="store_true", help="Emit the full report as JSON."
    )
    p_scan.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        default=None,
        help="Exit non-zero if any tool is at or above this severity (CI gate).",
    )
    p_scan.set_defaults(func=_cmd_scan)

    # keygen ---------------------------------------------------------------
    p_key = sub.add_parser("keygen", help="Generate an Ed25519 signing key for gateway records.")
    p_key.add_argument("--out", metavar="FILE", default=None,
                       help="Where to write the key (default: ~/.config/pramiti-mcp-gateway/signing.key).")
    p_key.set_defaults(func=_cmd_keygen)

    # proxy ----------------------------------------------------------------
    p_proxy = sub.add_parser(
        "proxy",
        help="Run the passive gateway in front of a downstream MCP server "
        "(logs + signs every tool call; never blocks).",
    )
    p_proxy.add_argument("--server-name", default="server",
                         help="Label for the downstream server in records.")
    p_proxy.add_argument("--records", metavar="FILE", default="pramiti-mcp-records.jsonl",
                         help="Where to append the signed record chain.")
    p_proxy.add_argument("--key", metavar="FILE", default=None,
                         help="Signing key file (default: resolve env/default; else unsigned).")
    p_proxy.add_argument("--url", metavar="URL", default=None,
                         help="Downstream remote server URL (SSE/HTTP) instead of a command.")
    p_proxy.add_argument("command", nargs="*",
                         help="Downstream server command, after '--'. e.g. -- npx -y server-github")
    p_proxy.set_defaults(func=_cmd_proxy)

    # posture --------------------------------------------------------------
    p_post = sub.add_parser("posture", help="Report the risk posture over a record log.")
    p_post.add_argument("records", help="Path to a gateway record JSONL file.")
    p_post.add_argument("--json", action="store_true", help="Emit the summary as JSON.")
    p_post.set_defaults(func=_cmd_posture)

    # verify ---------------------------------------------------------------
    p_ver = sub.add_parser("verify", help="Verify a record chain (hashes + signatures) offline.")
    p_ver.add_argument("records", help="Path to a gateway record JSONL file.")
    p_ver.add_argument(
        "--pubkey", metavar="HEX_OR_FILE", default=None,
        help="Pin verification to this Ed25519 public key (hex, or a file "
             "containing it). Without it, signatures are checked against the key "
             "stored in each record — which proves the log is internally "
             "consistent, not that it is YOUR log.",
    )
    p_ver.add_argument(
        "--allow-unpinned", action="store_true",
        help="Exit 0 on an unpinned pass. Without --pubkey a fabricated log "
             "passes, so it is exit 3 by default.",
    )
    p_ver.add_argument("--json", action="store_true", help="Emit the result as JSON.")
    p_ver.set_defaults(func=_cmd_verify)

    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
