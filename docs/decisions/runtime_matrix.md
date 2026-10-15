# Runtime, toolchain, ownership, and permission matrix

**Snapshot:** 2026-10-15 01:52 UTC. **Task:** FND-02 attempt 2, base `a970fe113f4ad0dfb88f407d1109fcd4841ac75d`, contract SHA-256 `9b058e21b28263db98f9bfbf9e5661ba98517aef2d369c61ae501dd2d6fcaaf0`.

This records observed local runtime and authority, not product verification. Tool versions and host/bootstrap details are retained from attempt 1 and linked below; this attempt updates the actor/runtime snapshot. Evidence paths are relative to `/Users/completetech/github/.scion-run/`.

## Runtime and toolchain

| Surface | Observed value | Evidence |
|---|---|---|
| Host | macOS, Apple Silicon client/worker host. | `evidence/bootstrap/environment.json`; `evidence/FND-02/attempt-1/runtime_probe.json` |
| Go | Go 1.27.2 at `.scion-run/toolchains/go/bin/go`. | `evidence/FND-02/attempt-1/runtime_probe.json`; `evidence/FND-02/attempt-1/runtime_evidence_manifest.json` |
| Python | `/opt/homebrew/bin/python3` is 3.14.4; PATH `python3` is 3.9.6. Use the explicit Homebrew path when the package requires the supported Python. | `evidence/FND-02/attempt-1/runtime_probe.json`; `evidence/bootstrap/environment.json` |
| Node.js | v24.15.0. | `evidence/FND-02/attempt-1/runtime_probe.json` |
| Git | 2.54.0, Apple Git 157. | `evidence/FND-02/attempt-1/runtime_probe.json` |
| Docker | 29.8.2, running Linux/aarch64 engine. This does not establish FUSE availability or authorize privileged containers. | `evidence/FND-02/attempt-1/runtime_probe.json`; `evidence/bootstrap/docker-ready.json` |
| CLI/runtime binding | Native CLI invocation uses `-m gpt-6-luna` for the Luna worker session. Sol reviewer sessions use `gpt-6.1-sol`. Director root model identity is not exposed. | Current native Herdr session/task packet; `evidence/FND-02/attempt-1/agent_snapshot.json` |

The bootstrap Go/Python/package validation records describe environment checks, not tests of product behavior. No product test is claimed here.

## Native sessions and dispatch

| Role | Current observation |
|---|---|
| Director | One root director session; model identity unexposed. |
| Active builders | Three native Herdr worker sessions: `canonical`, `runtime` (this FND-02 worker), and `security`. Count is the observed active builder set, not a slot estimate. |
| Reviewers | Sol reviewers are bound to `gpt-6.1-sol`; no reviewer session is counted as active in this snapshot. Reviews remain pending until actually run. |
| Dispatch | Run serially if a required worker/reviewer or runtime is unavailable. Do not infer active work from panes, configured targets, or theoretical capacity. |

## Shared build and contract ownership

The director added authoritative task FND-BUILD after FND-02. Designated owner `luna-build` owns only `go.mod`, `Makefile`, `toolchain.lock.json`, and `tools/check_toolchain.py`; it is a named assignment, not an active session until observed running. Do not edit these paths in FND-02. The designated owner must pin only versions observed or explicitly resolved by that task. (`evidence/FND-02/attempt-1/build-owner-decision.json`)

Shared dependencies and generated protobuf files have one named owner at a time. The director retains ownership until an exact-path task delegates each shared path. No concurrent shared-file ownership is authorized. Proposed PostgreSQL, Spanner, Cloud Storage, protobuf/gRPC, UI, and FUSE choices are design defaults, not verified adapters or private vendor internals. No dependency versions are asserted for them.

## Permitted actions and unavailable environments

| Action or environment | Current authority/status |
|---|---|
| Local edits and commits | Only the assigned isolated worktree and exact packet write paths. The director alone writes board state and shared build files. |
| Push, merge, publish | Disabled. All commits remain local. |
| Cloud tests/spend | No cloud verification; spend ceiling is $0. Do not provision resources. |
| Production, credentials, permissions | No production mutation, credential rotation, or permission broadening. |
| Containers | Ordinary local Docker use only; privileged containers are not authorized. |
| Linux FUSE | Unavailable/not verified. A Linux Docker engine alone does not establish FUSE support; leave the relevant gate blocked. |
| Product backends | No PostgreSQL, Spanner, Cloud Storage, or emulator verification is established by the cited bootstrap evidence. |

These limits follow the local execution contract and bootstrap runtime evidence. Report implementation and local, cloud, and scale verification separately; no cloud, FUSE, or scale capability is claimed by this matrix.
