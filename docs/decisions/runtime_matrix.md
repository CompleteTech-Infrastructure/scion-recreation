# Runtime, toolchain, ownership, and permission matrix

**Snapshot:** 2026-10-15 UTC (attempt 3; evidence captured at the timestamps in the linked records). **Task:** FND-02 attempt 3, base `390e581d7b480f40cf25c03a9c54a0f23dd66f53`, contract SHA-256 `226ebe960a4611660d5016a54c30bf3cc976a04a2a051306eca42f779da5e879`, lease expires `2026-10-15T02:48:31.672284+00:00`.

This records observed local runtime and authority, not product verification. Tool versions and host/bootstrap details are retained from prior snapshots and linked below; historical snapshots keep their original dates and paths. Evidence paths are relative to `/Users/completetech/github/.scion-run/`.

## Runtime and toolchain

| Surface | Observed value | Evidence |
|---|---|---|
| Host | macOS, Apple Silicon client/worker host. | `evidence/bootstrap/environment.json`; `evidence/FND-02/attempt-1/runtime_probe.json` |
| Go | Go 1.27.2 at `.scion-run/toolchains/go/bin/go`. | `evidence/FND-02/attempt-1/runtime_probe.json`; `evidence/FND-02/attempt-1/runtime_evidence_manifest.json` |
| Python | `/usr/bin/python3` is 3.9.6; `/opt/homebrew/bin/python3` is 3.14.4. PATH selection depends on the invoking environment: the native CLI shell resolved Homebrew Python 3.14.4; the director tool shell used Apple Python 3.9.6. Neither is a universal PATH result. Use the explicit supported `/opt/homebrew/bin/python3` path for package validation. | Explicit binary version commands: `evidence/FND-02/attempt-1/runtime_probe.json`; environment-specific PATH observations: `evidence/bootstrap/environment.json` and `evidence/FND-02/attempt-2/core-review-notes.md` (review probe at `2026-10-15T01:59:17.898121Z`). |
| Node.js | v24.15.0. | `evidence/FND-02/attempt-1/runtime_probe.json` |
| Git | 2.54.0, Apple Git 157 in the historical bootstrap probe. | `evidence/FND-02/attempt-1/runtime_probe.json` |
| Docker | 29.8.2, running Linux/aarch64 engine. This does not establish FUSE availability or authorize privileged containers. | `evidence/FND-02/attempt-1/runtime_probe.json`; `evidence/bootstrap/docker-ready.json` |
| CLI/runtime binding | Native worker session is Luna; the director root UI showed `GPT-6.1-Sol medium` at 2026-10-15 01:56:49 UTC. Assigned reviewer model is `gpt-6.1-sol`. These are task/UI observations, not inferred from titles. | `evidence/FND-02/attempt-3/herdr-prompt.txt`; `evidence/bootstrap/director-model-ui.json`; `evidence/bootstrap/herdr-working.json`; `evidence/FND-02/attempt-2/herdr-agents.json` |

Bootstrap Go/Python/package validation records describe environment checks, not product behavior. No product test is claimed here.

## Native sessions and dispatch

| Role | Point-in-time observation |
|---|---|
| Director | Root director UI footer showed `GPT-6.1-Sol medium`; captured command and output are in `evidence/bootstrap/director-model-ui.json`. Earlier tool-only Herdr metadata did not expose root model identity. |
| Assigned workers | At 2026-10-15 01:54:56 UTC, `canopy-canonical` and `canopy-security` were done, and `canopy-runtime` was working. This is a dated status snapshot, not a slot estimate. |
| Sol reviewers | At that same probe, `canopy-review` and `canopy-security-review` were observed working. Their terminal titles alone do not attest assignment or review scope; only director assignment and an actual review artifact do. |
| Dispatch evidence | Herdr state is time-specific. Probe metadata records exact commands and times in `evidence/FND-02/attempt-2/herdr-probe-meta.txt`; command outputs are in `evidence/FND-02/attempt-2/herdr-agents.json` and `herdr-working.ndjson`. Attempt 3's dispatch call timed out; see the bounded rule and walkthrough below. |

### Dispatch decision rule and observed cases

Use only native Herdr workers explicitly required and observed available for the assigned work; do not silently substitute hidden tool agents. Before dispatch, confirm the same task packet, unexpired lease, exact write paths, ownership, evidence location, and actual runtime handle. If capacity or tool availability is missing or uncertain, do not infer it. For ambiguous or timed-out dispatch, poll the same actual handle and inspect its state; never create a second writer for the same task. Run serially only if the same authorized task can actually execute with the identical packet, lease, ownership, evidence requirements, and independent review gates. Otherwise report the specific unavailable capability to the director as blocked and continue unrelated safe work. A missing independent reviewer leaves the work unaccepted. A mock cannot waive absent real Linux FUSE or cloud verification.

| Preserved case | Decision |
|---|---|
| Docker daemon was initially unavailable, then a later recorded probe observed a ready Linux/aarch64 engine. | Initial unavailable state proves no container/product conformance. The later ready state permits ordinary local container use only; it does not imply FUSE or privileged-container support. Evidence: `evidence/FND-01/attempt-1/source_inventory_manifest.json` (initial socket unavailable), `evidence/bootstrap/docker-ready.json` (ready probe). |
| Real Linux FUSE is unavailable/unverified on this host. | Real mount capability remains blocked; mocks cannot satisfy that gate. Bounded serial documentation work may continue when otherwise authorized and capable. Evidence: `evidence/FND-02/attempt-1/runtime_probe.json`; this document-only task packet. |
| Attempt 3 Herdr dispatch returned timeout (`timed out waiting for agent status`). | Do not interpret timeout as failure or completion and do not dispatch a duplicate writer. Repoll the same actual handle; if it remains unavailable, report that dispatch capability blocked to the director. This documentation work may proceed in its already assigned worktree under the existing packet and lease. Evidence: `evidence/FND-02/attempt-3/dispatch-result.json`. |

## Shared build and contract ownership

The director added authoritative task FND-BUILD after FND-02. Designated owner `luna-build` owns only `go.mod`, `Makefile`, `toolchain.lock.json`, and `tools/check_toolchain.py`; it is a named assignment, not an active session until observed running. Do not edit these paths in FND-02. The designated owner must pin only versions observed or explicitly resolved by that task. (`evidence/FND-02/attempt-1/build-owner-decision.json`)

Shared dependencies and generated protobuf files have one named owner at a time. The director retains ownership until an exact-path task delegates each shared path. Proposed PostgreSQL, Spanner, Cloud Storage, protobuf/gRPC, UI, and FUSE choices are design defaults, not verified adapters or private vendor internals. No dependency versions are asserted for them.

## Permitted actions and unavailable environments

| Action or environment | Current authority/status |
|---|---|
| Local edits and commits | Only the assigned isolated worktree and exact packet write paths. The director alone writes board state and shared build files. |
| Remote push, remote merge, publication | Disabled. Local exact-reviewed integration is authorized and required, and may be performed only by the director after independent review. All commits remain local. |
| Cloud tests/spend | No cloud verification; spend ceiling is $0. Do not provision resources. |
| Production, credentials, permissions | No production mutation, credential rotation, or permission broadening. |
| Containers | Ordinary local Docker use only; privileged containers are not authorized. |
| Linux FUSE | Unavailable/not verified. A Linux Docker engine alone does not establish FUSE support; leave the relevant gate blocked. |
| Product backends | No PostgreSQL, Spanner, Cloud Storage, or emulator verification is established by the cited bootstrap evidence. |

These limits follow the local execution contract and bootstrap runtime evidence. Report implementation and local, cloud, and scale verification separately; no cloud, FUSE, or scale capability is claimed by this matrix.
