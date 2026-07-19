# pramiti-mcp-gateway

**See what your AI agents can actually _do_.**

An open-source security posture scanner for [Model Context Protocol (MCP)](https://modelcontextprotocol.io)
servers. Point it at a server's tools and it tells you, in two minutes, which
ones let an agent take dangerous actions — writes, irreversible operations,
sensitive-data exfiltration, and arbitrary-execution power — with zero
infrastructure and no changes to anything you run.

MCP gives AI agents hands. This tells you what those hands can reach.

```
$ pramiti-mcp-gateway scan tools.json

MCP Security Posture
============================================================
9 tools scanned  |  read 3  write 6  unknown 0
severity:  critical 4  high 1  medium 1  low 1  info 2
------------------------------------------------------------
[CRIT] internal_db.export_patient_records
        Changes state; effects are hard to reverse; touches sensitive/regulated data; grants broad or unconstrained capability.
        signals: irreversible:export, sensitive:patient, sensitive:medical, overbroad:no-input-schema
[CRIT] internal_db.run_sql
        Changes state; effects are hard to reverse; grants broad or unconstrained capability.
        signals: irreversible:execute, irreversible:run, overbroad:sql, overbroad:arbitrary
[CRIT] payments.transfer_funds
        Changes state; effects are hard to reverse; touches sensitive/regulated data.
[HIGH] github.delete_repository
[MED ] github.create_pull_request
[LOW ] payments.list_transactions
[INFO] github.get_file_contents
------------------------------------------------------------
Top risk: CRITICAL. These tools let an agent take high-impact actions.
Gate them before giving an agent write access.
```

## Why this exists

An MCP server can expose a `delete_repository`, a `transfer_funds`, or a
`run_sql` tool right next to a harmless `search`. When you connect an AI agent
to it, the agent can call any of them — and if the agent is prompt-injected, it
_will_ be talked into calling the wrong one. Prompt-level defenses don't help
here: the danger isn't what the agent _says_, it's what it can _do_.

Before you can gate agent actions, you have to see them. This scanner is the
"see them" step, and it's free.

## Install

```bash
# zero dependencies — run it with no install:
uvx pramiti-mcp-gateway scan tools.json
# or
pipx run pramiti-mcp-gateway scan tools.json
# or install it:
pip install pramiti-mcp-gateway

# to scan your live servers by connecting to them, add the 'connect' extra:
pip install 'pramiti-mcp-gateway[connect]'
```

## Usage

`scan` takes a JSON manifest of MCP tools — the shape an MCP `tools/list`
response returns — and classifies each tool's action risk:

```bash
pramiti-mcp-gateway scan tools.json           # human-readable report
pramiti-mcp-gateway scan tools.json --json     # machine-readable JSON
cat tools.json | pramiti-mcp-gateway scan -    # read from stdin
```

**Accepted manifest shapes:**

```jsonc
// a raw tools/list result
{ "tools": [ { "name": "delete_repo", "description": "...", "inputSchema": {} } ] }

// a bare list of tools
[ { "name": "get_file", "description": "..." } ]

// multiple servers at once
{ "servers": { "github": { "tools": [ ... ] }, "payments": { "tools": [ ... ] } } }
```

### Scan your live servers (`--config`)

Point it at your MCP client config — the `mcpServers` shape used by Claude
Desktop, Cursor, and others — and it connects to each server, enumerates its
real tools, and scans them. Both local (stdio) and remote (SSE / streamable
HTTP) servers are supported.

```bash
pramiti-mcp-gateway scan --config ~/.config/claude/claude_desktop_config.json
pramiti-mcp-gateway scan --config mcp.json --timeout 15 --json
```

```jsonc
// mcp.json
{
  "mcpServers": {
    "github":   { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] },
    "payments": { "url": "https://mcp.internal.example.com/sse" }
  }
}
```

`tools/list` is a read-only protocol call and never executes a tool. Scanning a
**stdio** server does start its process (the only way to speak the protocol to
it), so `--config` connects only to servers you configured. A server that fails
(bad command, unreachable URL, timeout) produces a warning and is skipped — one
bad server never aborts the scan. Live connect needs the `connect` extra; the
offline manifest `scan` stays dependency-free.

### Watch live traffic (passive gateway)

Put the gateway *between* an agent and its MCP server. It forwards every call
unchanged — it never blocks, so there is zero production risk — and appends a
signed, hash-chained record of each tool call. Install it by pointing your
agent's config at the gateway instead of the server:

```jsonc
{
  "mcpServers": {
    "github": {
      "command": "pramiti-mcp-gateway",
      "args": ["proxy", "--server-name", "github", "--records", "github.jsonl",
               "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

```bash
pramiti-mcp-gateway keygen                 # one-time: Ed25519 signing key
pramiti-mcp-gateway posture github.jsonl    # what did my agents actually do?
pramiti-mcp-gateway verify  github.jsonl    # is the evidence intact & signed?
```

`posture` reports risk over time — calls by severity, by server, and the
most-called risky tools. `verify` recomputes the hash chain and checks every
Ed25519 signature offline, so anyone can confirm the log wasn't altered. Raw
tool arguments are never stored — only their `sha256` — so the evidence log
never becomes a place secrets leak to.

**See it in action:** `python examples/demo.py` runs a compromised agent trying
to exfiltrate PHI through a real MCP server, and shows the gateway catching and
proving it. (Needs `pip install 'pramiti-mcp-gateway[gateway]'`.)

### Use it as a CI gate

Fail a build if any tool is at or above a severity — so a new high-risk tool
can't land in your agent's reach without review:

```bash
pramiti-mcp-gateway scan tools.json --fail-on high
# exit code 2 if any tool is 'high' or 'critical'
```

## How it classifies (and its limits)

The scanner reads only what a tool _declares_ about itself — its name,
description, and input schema. From that it scores four axes and rolls them into
one severity:

| Axis | What it means |
|---|---|
| **Access** | read / write / unknown |
| **Reversibility** | can the effect be undone? (delete, transfer, send, export → no) |
| **Sensitivity** | does it touch regulated / sensitive data? (PHI, PII, cards, credentials) |
| **Breadth** | does it grant arbitrary power? (SQL, shell, exec, or a write with no schema) |

It is a **heuristic** and it is deliberately **fail-loud**: an unclassifiable
write is flagged for review, never waved through. It cannot know a server's real
runtime behavior, so treat a clean report as "no _declared_ red flags," not a
proof of safety. It is deterministic — the same tool always scores the same
way — so results are safe to diff in CI.

## Roadmap

- **Live connect** (`scan --config`) — connect to your configured MCP servers,
  enumerate their real tools, and scan them. ✅ _shipped_
- **Passive gateway** (`proxy` + `posture`) — sit between an agent and its MCP
  servers, log and sign every tool call, and report posture over time. No
  blocking, no production risk. ✅ _shipped_
- **Verify** (`verify`) — check the signed record chain offline. ✅ _shipped_

Seeing the risk is free. **Stopping** it — deterministic allow/deny/rewrite
policy on agent actions, cryptographic attestation of every decision, and
compliance evidence — is [Praxom](https://getpramiti.com), the commercial
control plane this scanner is carved from.

## License

MIT © Pramiti Labs
