# Changelog

All notable changes to this package are documented here.
The version heading matches ``__version__`` in the package ``__init__``.

## [0.2.0] - 2026-10-06

### Added

- Record format v2: `RecordStore.append()` takes two new keyword arguments, `classification` and `decisions`. Passing either one writes a v2 record with `classification`, `decisions` and `version` (`RECORD_VERSION = 2`) inside the hashed and signed payload (`PAYLOAD_FIELDS_V2`). Omitting both writes the same v1 record as 0.1.0. `pramiti-agentguard` requires `pramiti-mcp-gateway>=0.2` because it calls `append()` with these arguments. (d5aa5cb54)
- `verify_records()` reads both v1 and v2 records. A record whose `version` it does not recognise produces an `unknown_version` issue and is not treated as v1. (d5aa5cb54, 8343154f1)
- Key pinning: `verify_records(records, expected_public_key=...)` reports a `wrong_key` issue for any record signed by a different key. `VerifyResult` has a new `advisories` list, which is also in `to_dict()`. It carries `unpinned_key` when signatures were checked only against keys stored in the records, and `mixed_keys` when one chain uses more than one key. (3c610a071)
- `pramiti-mcp-gateway verify` has two new flags. `--pubkey HEX_OR_FILE` pins verification to a key. `--allow-unpinned` lets an unpinned pass exit 0. Advisories are now printed in text output as well as in `--json`. (06dac749e)
- Chain-tip witness: every append writes `{seq, record_hash}` to `chain_tips.json` beside the log, under a file lock. `verify` reports `truncated` when records were removed from the end of the log and `tip_mismatch` when the last record differs from the witness. If the witness is missing or has no entry for the log, `verify` adds a `no_witness` advisory. New helpers in `records`: `TIPS_FILENAME`, `write_chain_tip`, `load_tips_beside`, `chain_tip_issues`, `read_tips_file`. (d6c816da6, 598174aa2)
- `PostureReport.unreadable` (server name to reason) lists servers and tool entries that could not be read or reached. It appears in `to_dict()` as `unreadable` and as `summary.unreadable_servers`, and text output lists it under an `UNREADABLE:` heading. (8269b861d, 464ba8ff8)
- `scan_manifest()` accepts a server entry given as a bare list of tools (`{"servers": {"db": [...]}}`). In 0.1.0 such an entry was read as zero tools. (7c1517eb8)
- The package ships a `py.typed` marker. (3fe457c38)

### Changed

- Breaking: `requires-python` is now `>=3.11,<3.14` (was `>=3.9`). The 3.9 and 3.10 classifiers were removed. (3fe457c38)
- Breaking: `pramiti-mcp-gateway verify` exits 3 when a signed log passes only against keys carried inside the log. In 0.1.0 it exited 0. Pass `--pubkey` or `--allow-unpinned` to get exit 0. (06dac749e)
- Breaking: `RecordStore(path)` verifies the whole existing chain before resuming: linkage, dense `seq`, hash recompute, and no fields outside the payload. If the chain does not verify, it raises the new `TamperedChainError`. The `proxy` command prints the error and exits 1 instead of appending. (28313abf7)
- Breaking: `verify_records()` reports an `unauthenticated_fields` issue for any record key outside the hashed payload and the derived fields (`record_hash`, `signature`, `public_key`). Logs carrying extra keys that passed in 0.1.0 now fail. (8343154f1)
- Breaking: `scan` exits 1 with a `NO POSTURE` message when no tool was inspected and at least one server could not be read or reached. In 0.1.0 this case exited 0 with "No high-severity action tools detected". With `--config`, servers that fail to connect now count toward this check. (912b4a0df, 464ba8ff8)
- `pramiti_mcp_gateway.records` imports `fcntl` at module level, so the record store, `proxy` and `verify` now need a POSIX platform. The offline `scan` path does not import it. (d6c816da6)
- The `connect` and `gateway` extras pin `mcp>=1.0.0,<2`. mcp 2.0 removed the server decorators that `proxy` uses. (ead7b4541)
- Packaging metadata: the version is read from `pramiti_mcp_gateway.__version__`, the license is the SPDX string `MIT`, and an `authors` entry was added. (85ca81bf8, 3fe457c38, f25e9be9a)

### Fixed

- The passive proxy returns the downstream `CallToolResult` unchanged. In 0.1.0, downstream errors reached the agent as successes and `structuredContent` was dropped. (2d1d586c0)

### Security

- `write_keypair()` creates the private key file with mode 0600 at `os.open` time. In 0.1.0 the file was written first and chmod'd afterwards. A failed chmod now raises instead of being ignored. (28313abf7)

## [0.1.0] - 2026-07-20

First PyPI release, uploaded from the public mirror vasamsetty86/pramiti-mcp-gateway
(tag v0.1.0). Its history is in git.
