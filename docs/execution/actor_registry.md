# Local actor registry and controller rehearsal

Observed **2026-10-15 02:36:28–02:36:29 UTC** (2026-10-14 EDT), Herdr session `default`, workspace `w2G`. This is an ephemeral inventory, not a capacity promise or an authentication service. **Nine dedicated worker/reviewer/lead lanes** (`p3`–`p9`, `pA`, `pB`) are distinct from **one director/coordinator** (`p2`). An additional extraction session (`p1`) is outside both counts. The historical four-slot/tool-agent description does not describe this setup. Internal tool helpers are not additional native lanes or independent board identities.

Scope: FND-10 attempt 1, actor `sol-herdr-registry`, base `2c36afd3a244ac6b09f67b5706fdc94cf28b4e3f`, contract `0261c136704e7b4b7621fd871895bea13dc669eabc9bbaf67bf9be089a1977ed`. The only product lease is this file, expiring `2026-10-15T03:17:52.301923+00:00`. [Packet][packet] and [preflight][preflight] retain exact contract inputs and accepted dependencies: FND-02 attempt 3 at `cd7c35e6a64c5fcdfbd7b5ec2a2ea81e7c5c3e0c`; FND-OWNERSHIP attempt 1 at the base above.

## Runtime-to-actor bindings (C1)

The [fresh list][list] supplies names/states; the [capture manifest][runtime] indexes timestamped process arguments, detection footers and recent output for every pane. All nine dedicated lanes have a live native Codex process with explicit **`gpt-6.1-sol`, reasoning `ultra`, service tier `ultrafast`**, corroborated by their footers. No configuration was changed. “Done” is Herdr's observed readiness state, not board acceptance. There were two working and seven done dedicated lanes at capture.

Paths in the project column are relative to `/Users/completetech/github/`. Every dedicated lane's OS/process cwd and Herdr `foreground_cwd` reported `src`; explicit Codex `-C` and the footer identify the project below. A reviewer can examine another worktree without changing its launch project.

| Native name / pane | Board actor binding | Role and observed assignment | Herdr state | Launch project (`-C` and footer) | Binding evidence |
|---|---|---|---|---|---|
| `canopy-control-review` / `w2G:p3` | `canopy-control-review` | Core reviewer; latest output writes FND-11 attempt 1 rework review. Older title still says FND-04. | working | `.scion-run/worktrees/FND-04` | [Process][p3]; [actual FND-11 review][review11] |
| `canopy-security-review` / `w2G:p4` | `sol-herdr-security-review` | Security reviewer; FND-05 attempt 1 review says rework. | done | `src` | [Process][p4]; [actual review][review5s] |
| `canopy-build` / `w2G:p5` | `luna-build` | FND-BUILD attempt 1 author; footer reports candidate `d71d469f5c3c411833a910c38b8434de164802d0`, awaiting independent review/integration. Actor's `luna` label does not describe the observed Sol model. | done | `.scion-run/worktrees/FND-BUILD` | [Process][p5]; [packet][buildpacket] |
| `canopy-registry` / `w2G:p6` | `sol-herdr-registry` | FND-10 attempt 1 author, this registry and isolated rehearsals. | working | `.scion-run/worktrees/FND-10` | [Process][p6]; [packet][packet]; inherited caller pane in [manifest][runtime] |
| `canopy-review` / `w2G:p7` | `sol-herdr-review` | Core reviewer; FND-05 attempt 1 review says rework. | done | `src` | [Process][p7]; [actual review][review5c] |
| `canopy-core-lead` / `w2G:p8` | **Unbound**: no explicit board actor ID in this dispatch | Core planning lead; FND-BUILD → FND-07/storage/query readiness report completed. | done | `src` | [Process][p8]; [dispatch][corelead]; recent output indexed in [manifest][runtime] |
| `canopy-test-operator` / `w2G:p9` | **Unbound**: no explicit board actor ID in this dispatch | Independent verifier; combined FND-04/05 descriptor and canonical fixture report completed, no approval issued. | done | `src` | [Process][p9]; [dispatch][verifier]; recent output indexed in [manifest][runtime] |
| `canopy-security-lead` / `w2G:pA` | **Unbound**: no explicit board actor ID in this dispatch | Security planning lead; adversarial matrix and proposed packets completed, no product verification claimed. | done | `src` | [Process][pA]; [dispatch][securitylead]; recent output indexed in [manifest][runtime] |
| `canopy-build-review` / `w2G:pB` | `sol-herdr-build-review` | Independent FND-OWNERSHIP attempt 1 reviewer; recorded pass at exact base SHA above. | done | `src` | [Process][pB]; [actual review][reviewownership] |

Six lane-to-board-actor bindings are supported; three lanes have evidenced roles but no board identity binding. Their smallest missing input is an explicit director/runtime record assigning an actor ID to that same live pane/session. Do not derive one from a name, title, model, or suggested role template.

The separate coordinator is board actor **`sol-director`**, named as lead by current packets and acceptor by both dependency acceptances. Its association with unnamed `w2G:p2` is recorded in the [director bootstrap observation][director]; the fresh list reports `working`, process project/cwd is `github`, and argv is `codex --yolo` without explicit model settings. The current detection capture shows the session selector, not a model footer, and the recent-output read failed (preserved as [raw failure][p2failure]). Thus `gpt-6.1-sol medium` is a **historical** 01:56:49 UTC footer observation; current model/reasoning/tier and renewed identity corroboration are **unverified**. Unnamed `w2G:p1` is the separate idle package-extraction session; footer `GPT-6-Astra low`, no board actor binding.

The [frozen dispatch observation][dispatch] embeds the 02:32:14 root snapshot and a 02:35:23 list. Its snapshot has `canopy-ownership` on p5 and `canopy-qualification` on p6; by the fresh capture those panes had been reused for build and registry. FND-11 actor `sol-herdr-qualification` is therefore a historical p6 binding, not another current lane. The current FND-04 attempt 2 and FND-05 attempt 2 packets name `sol-herdr-control-rework` and `sol-herdr-objects-rework`, but this fresh nine-lane capture has no matching author processes: **launch-pending/unbound at this observation**, not verified active writers. Packet copies and hashes are indexed in [manifest][runtime]. None of the nine dedicated lanes was shell-only in the fresh capture.

## Authority and lifecycle

**Only the director writes the real board**, including its database, state, exports and dashboards. Workers return artifacts; they never claim, submit, review, integrate, accept or close their own real-board task. This worker made no real-board initialization or acceptance claim.

Before the director claims work, verify accepted prerequisites, existing implementations/reviews, exact path ownership, actual runtime capacity, an isolated worktree and a unique attempt branch. A claim records one actor and a bounded write lease; overlapping file/directory scopes cannot coexist. Expiry does not prove a writer stopped or permit automatic reassignment. A blocked owner retains its scope until the director obtains stopped-writer evidence and recovers into a fresh attempt. Scope/contract changes and budget overruns require a lead handoff.

Submission commits a concrete change inside the exact lease and supplies base/candidate SHAs, contract digest, criterion evidence and executed tests. Stop writing after submission. Review targets that exact candidate, requires a different actor and `model_alias=sol61`; high-risk work requires two distinct reviewers and any required specialty. Review correctness and test adequacy, not merely an author's summary. Any code change requires fresh review. Integration uses a separate actor and preserves the reviewed candidate through fast-forward or Git's clean merge tree; extra edits/conflict resolutions require a new reviewed candidate. Independent acceptance requires the exact integration SHA, accepted prerequisites, all criteria and verification in the required environment. A historical pass does not verify a later integration or release.

`board.py` accepts actor strings and checks their relationships; **it cannot authenticate the person, model, runtime or reviewer independence**. Herdr/process records and explicit dispatch/review records are external identity evidence, not cryptographic attestation. A tab title alone is not actor authentication. The controller checks local SQLite transitions, exact Git commit/path/tree identity, evidence existence/digests and test-record fields; it cannot establish that claimed tests ran or that runtime behavior is correct. SQLite transactions are local atomic coordination, not distributed leases or a formal lock-freedom claim. Protect the board and artifacts with host access controls; never use digest knowledge as permission to obtain product objects or metadata.

## Executed disposable rehearsals (C1/C2)

All files below are outside the product worktree under [attempt evidence][attempt]. The extracted package has no Git revision: [package pin][pin] records all file hashes and validates all **65** manifest entries. Pinned `board.py` SHA-256 is `8b2aa1f2ec32e49de964357366566b6e4becc1527003e88c33b41c29a492898a`; `test_board.py` is `77c4b5f5a3e6b28bcf05d37c4a3ff481a542ddd9168a21cc2ccca3220f45980f`.

The real package controller was invoked with an explicit **rehearsal workspace on every call**. All four commands exited 0: [init][init] created `rehearsal/initialized-board/.state/board.sqlite` with 151 tasks and zero accepted; [validate][validate] returned valid with zero evidence files; [status][status] reported 151 pending, no expired writers/blockers; [ready][ready] returned only FND-01. This is the immutable package plan in a disposable board, not the amended real board.

Five unchanged, pinned `test_board.LifecycleTests` methods then executed actual `Board.init`, schema-valid synthetic tasks/artifacts and real Git repositories/commits. The [runner][runner] only retains temporary fixtures, traces calls, disables Git hooks/signing and validates the published task/review/criterion schemas. There is no published submission/integration schema; those artifacts pass the real controller's structural checks. Fixtures and complete stdout/stderr remain under [successful run 2][run2].

| Exact test suffix (prefix `LifecycleTests.`) | Observed result |
|---|---|
| `test_full_lifecycle_unlocks_dependent` | PASS: A moves claim → submit → independent synthetic review → fast-forward integration → acceptance; B becomes ready; validate succeeds and export contains three tasks. |
| `test_self_review_rejected` | PASS: `Board.review('A', 'evidence/review.json')` with reviewer `builder`, equal to the author, rejects with **`Independent Sol reviewer required`**. |
| `test_overlapping_scope_rejected` | PASS: after `Board.claim('A', 'builder')` owns `a.txt`, `Board.claim('C', 'other')` rejects with **`Write scope conflicts with A`**. |
| `test_fake_commit_sha_rejected` | PASS: submission naming forty `f` characters rejects during `git cat-file -t` with **`could not get object info`**. This is the nonexistent candidate case, separate from integration forgery. |
| `test_clean_integration_rejects_extra_unreviewed_code` | PASS: after genuine submission/review, the fixture adds `extra.txt` and commits **`unreviewed extra`**. Its integration artifact names that real descendant SHA and matching test-record revision. `Board.integrate('A', 'evidence/integration.json', repo)` rejects with **`Integration tree differs from the clean reviewed merge; fresh review required`**. The commit exists and contains the candidate; its tree differs from `git merge-tree --write-tree base candidate`. |

Each test ran once in successful run 2, zero failures/errors/skips. Each log is named exactly `<test suffix>.log`; its sibling fixture directory retains the synthetic package, board, artifact JSON and `.git`. [Initial run][run1] is preserved: the tests themselves reported OK, but four wrapper invocations exited 1 because the evidence collector lacked schema `const`/`pattern` support or could not serialize `Path` arguments; the overlapping test exited 0. The corrected wrapper did not change the pinned controller/tests.

These are **controller mechanics only**. Synthetic `builder`, `reviewer-1`, `integrator`, `acceptor` and synthetic test-record strings prove neither authenticated independent agents nor product test execution. Status: **implemented** registry documentation; **verified-local** runtime observations and controller rehearsals; **verified-cloud: not run**; **verified-scale: not run**. Product behavior is not verified by this task.

## Refresh and reproduce

Refresh before dispatch or reusing a pane. Run [capture_runtime.py][capture] to create a new timestamped directory, then compare `herdr --session default agent list`, `pane process-info --pane <observed-id>`, and `agent read <observed-id> --source detection --lines 18` against current packets and actual review/dispatch records. Record raw stdout/stderr, exits and timestamps; inspect missing/changed bindings without guessing. Preserve failed reads, distinguish `done` from accepted, and request only the missing binding record from the director. The capture fixes workspace `w2G` for this run; re-establish the workspace from the absolute product path if topology changes.

```sh
E=/Users/completetech/github/.scion-run/evidence/FND-10/attempt-1
P=/Users/completetech/github/prompts/scion-agent-prompt-package
/opt/homebrew/bin/python3 "$E/capture_runtime.py"
# Fresh disposable name: init deliberately refuses to overwrite an existing board.
W="$E/rehearsal/initialized-board-NEW"
/opt/homebrew/bin/python3 "$P/tools/board.py" --workspace "$W" --package "$P" init
/opt/homebrew/bin/python3 "$P/tools/board.py" --workspace "$W" --package "$P" validate
/opt/homebrew/bin/python3 "$P/tools/board.py" --workspace "$W" --package "$P" status
/opt/homebrew/bin/python3 "$P/tools/board.py" --workspace "$W" --package "$P" ready
# Uses the pinned package; choose a new run ID to preserve earlier output/fixtures.
/opt/homebrew/bin/python3 "$E/rehearsal.py" --rerun-tests --run-id run-NEW
```

Never omit `--workspace` or replace `W` with `/Users/completetech/github/.scion-run`. [Command records][runs] contain exact executed commands (the Python symlink resolved to `/opt/homebrew/opt/python@3.14/bin/python3.14`), exits, timestamps and complete output. The package [controller README][readme] defines these operations. Refresh external evidence without treating this document as a live board.

[attempt]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/
[packet]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/packet.json
[preflight]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/preflight.json
[runtime]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/manifest.json
[list]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/agent-list.json
[dispatch]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/dispatch-observation.json
[director]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/source-records/evidence/bootstrap/director-model-ui.json
[p2failure]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/w2G-p2-recent.json
[p3]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/w2G-p3-process.json
[p4]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/w2G-p4-process.json
[p5]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/w2G-p5-process.json
[p6]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/w2G-p6-process.json
[p7]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/w2G-p7-process.json
[p8]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/w2G-p8-process.json
[p9]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/w2G-p9-process.json
[pA]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/w2G-pA-process.json
[pB]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/w2G-pB-process.json
[review11]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/source-records/evidence/FND-11/attempt-1/core-review.json
[review5s]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/sources/evidence/FND-05/attempt-1/security-review.json
[review5c]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/sources/evidence/FND-05/attempt-1/core-review.json
[reviewownership]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/sources/evidence/FND-OWNERSHIP/attempt-1/build-review.json
[buildpacket]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/runtime/20261015T023628097340Z/sources/evidence/FND-BUILD/attempt-1/packet.json
[corelead]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/source-records/research/canopy-core-lead-dispatch.txt
[verifier]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/source-records/research/canopy-test-operator-dispatch.txt
[securitylead]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/source-records/research/security-lead-dispatch.txt
[pin]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/rehearsal/package-pin.json
[runner]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/rehearsal.py
[capture]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/capture_runtime.py
[init]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/rehearsal/board-init.log
[validate]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/rehearsal/board-validate.log
[status]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/rehearsal/board-status.log
[ready]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/rehearsal/board-ready.log
[run1]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/rehearsal/runs.json
[run2]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/rehearsal/test-runs/run-2/runs.json
[runs]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/rehearsal/runs.json
[readme]: /Users/completetech/github/.scion-run/evidence/FND-10/attempt-1/rehearsal/pinned-package/tools/README.md
