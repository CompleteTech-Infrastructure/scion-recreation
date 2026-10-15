# OBJ-01 — canonical object codec acceptance parent

Author: `sol-codec-accept2`, attempt 2, documentary repair. **Attempt-1 lifecycle history:** `sol-codec-accept1` prepared the prior author-stage document before host commit; candidate `ccc48fc554fcf7a1c5f85896565329397d9ec746` was subsequently locally host-committed and submitted for review. The original [CORE][prior-core] and [security][prior-security] reviews returned rework, as preserved in the [root collection][review-collection] and [stopped-writer record][prior-stopped]. **Historical attempt-2 author-stage snapshot at `2026-10-15T13:04:21.855575+00:00` (original author handoff freeze):** at that time, the candidate commit, board submission, two fresh independent Sol reviews (including CORE), integration, integration verification, and acceptance were pending. Accepted child reviews did not approve this successor document; the author cast no vote at that historical snapshot. Subsequent and current commit, board submission, review, integration, and acceptance status are determined by director records, not by this historical document snapshot.

**Prior supporting product evidence:** the attempt-1 parent run tested unchanged code at predecessor `2181e878956c91de50aaa15a6c91ff68389afeca`, branch `work/OBJ-01/attempt-1`. Its 173 model and 119 conformance leaves are historical support, not attempt-2 candidate verification or integration execution. This repair starts at `08e1597ed82cf05bb50556e959b5849766b87b31`, branch `work/OBJ-01/attempt-2`, in the leased `/Users/completetech/github/.scion-run/worktrees/OBJ-01-2`. The [original task][task], [attempt-1 packet][packet], [attempt-1 launch pins][pins], [attempt-2 frozen packet][packet2], [copied input pins][pins2], [AGENTS.md](../../../AGENTS.md), and frozen contract govern. [Attempt-1 input verification][inputs] is historical; [attempt-2 pin verification][pins2-verified] confirms all 34 copied inputs against their listed source bytes, hashes and sizes, and recomputes the nine-input sorted length-prefixed contract SHA-256 `b605165aff083149d91250003eb2b47648fb668ec412eb912fef81e85d50d3d7` (64 characters). The [dispatcher reconciliation][digest-reconciliation] establishes that the extra `d` in the old 65-character review-dispatch literal was a dispatcher-only typo; original prompts, pins and reviews remain unchanged. The service catalog is the external prompt-package contract pinned under the attempt-2 inputs, not a Git blob. The canonical contract component remains `eceab23e153e7d96558858ef76448d41b34bf844315b5d37cea4f0404df4b9c2`.

The original acceptance criteria remain verbatim:

| Criterion | Required text | Author evidence assessment |
|---|---|---|
| C1 | Encode/decode typed canonical objects and reproduce independent logical digest vectors. | Prior `verified-local` supporting evidence; exact source and test identities below. Historical author-stage snapshot at `2026-10-15T13:04:21.855575+00:00`: successor verification and acceptance were pending; subsequent/current status is determined by director records. |
| C2 | Alternate compression encodings preserve logical IDs while corrupt or noncanonical values fail. | Prior `verified-local` supporting evidence within the precise tested conformance envelope below. Historical author-stage snapshot at `2026-10-15T13:04:21.855575+00:00`: successor verification and acceptance were pending; subsequent/current status is determined by director records. |

**Dependency boundaries and identities.** These are separate accepted sources and test revisions. [Historical records][history], [source identity checks][sources], and [raw test reconciliation][historical-tests] bind their original freezes, exact reviews, acceptance records and integrated outputs. All 1,631 unique direct criterion references in the dependency acceptance files are present and nonempty ([reference audit][reference-audit]); existence alone is not behavioral proof.

| Dependency | Reviewed candidate → accepted integration | Contribution and direct records |
|---|---|---|
| FND-03 | `390e581d7b480f40cf25c03a9c54a0f23dd66f53` → same | Canonical v1 contract/oracle, not a runtime parser. [Acceptance][f03], [submission/source binding][f03-source], [CORE][f03-core], [security][f03-sec], [integration][f03-int], [19-vector integration output][f03-log]. |
| FND-07 | `718dfe8ec011e0c5fe39ad6035dc012bf6bb1585` → `9fbcf1f09ac68752c67603ceec6ffe6ab7d5efe3` | Deterministic local harness and fail-closed required-test selection, not codec behavior. [Acceptance][f07], [source freeze][f07-source], [exact CORE review][f07-core], [integration][f07-int]. |
| OBJ-01-A | `1866146b59e21460daae4ea2fd68e0e11968e691` → same | Typed immutable values, byte paths, validation and alias isolation. [Acceptance][a], [freeze][a-source], [CORE][a-core], [security][a-sec], [integration][a-int], [84 focused model leaves][a-log]. |
| OBJ-01-B | `6341a083089a6e881f066e3dcfe5d53303740b76` → `a4857323f200f5c6e58c1db0ebd04ca48280dacd` | Production uncompressed canonical encode/hash and bounded streaming. [Acceptance][b], [freeze][b-source], [CORE][b-core], [security][b-sec], [integration][b-int], [124 focused model leaves][b-log]. |
| OBJ-01-C | `487b38c3694f63b9d98fd76e4d4aa26244d26ac3` → `aa968eb8f4c11d6cf86d9061b6ab9b40b3557338` | Production canonical decoding and rejection. [Acceptance][c], [accepted v3 freeze][c-source], [CORE][c-core], [security][c-sec], [integration][c-int], [173 focused model leaves][c-log]. Earlier source freezes remain historical. |
| OBJ-01-D | `ec97b3a40d3a06b9450c5b4f0c2e3e1530e71c7f` → `2181e878956c91de50aaa15a6c91ff68389afeca` | Independent conformance/oracle and bounded compression fixtures. [Acceptance][d], [original frozen test source][d-source], [postcommit binding][d-binding], [corrected exact CORE review][d-core], [security][d-sec], [integration][d-int], [119 integrated conformance leaves][d-log]. |

The attempt-1 base preserved all eleven checked dependency source files byte-for-byte at their reviewed and integrated identities. D's [test source](../../../tests/conformance/object_codec_test.go) SHA-256 is `6ebe2820ab5df0f2f5a6911ea92522b9faf76127f28d000aca204c30d51a764c`; its [fixture](../../../tests/conformance/testdata/canonical_v1.json) is `7a6f437992a89e7450b2c579f3e4778f2f66dcb7fcb701ead7b83432d87e882d`. A/B/C implementation and test hashes are recorded individually in [attempt-1 source identity checks][sources]. Byte identity is not a product execution on this successor.

**Criterion evidence map.** The [exact criterion record][criteria] enumerates only the **119 conformance identities: 23 C1 and 96 C2**, with package-qualified names and run/pass line numbers in two prior streams: [D's accepted conformance integration stream][d-log] and the [attempt-1 parent model/conformance stream][fresh-raw], both on predecessor `2181e878956c91de50aaa15a6c91ff68389afeca`. This two-stream assertion applies only to the conformance rows below. D's [original criterion map][d-criteria] supplies the fixed 23/96 identities; its initially uncommitted metadata is supplemented by the exact postcommit binding and integrated records above. The separate [model-selection inventory][fresh-selection] enumerates **173 model leaves** in `canopy.local/canopy/internal/model`: its C1 groups include 19 encode/hash leaves, 19 literal-decode leaves, and one constructed-roundtrip leaf. Their supporting streams are [B model][b-log] (124 total model leaves, including the 19 encode/hash leaves), [C model][c-log] (173, including all three groups), [D's accepted model regression][d-model-log] (173), and the [attempt-1 parent stream][fresh-raw] (173 model leaves plus the separate conformance package). Model identities are not conformance rows and do not occur in D's focused-conformance stream. These historical model runs occurred at their respective B/C/parent revisions in the dependency table, not against this successor.

| Criterion | Exact tests and source | Direct evidence and meaning |
|---|---|---|
| C1 (model support) | `canopy.local/canopy/internal/model`: `TestEncodeAndHashFrozenCanonicalVectors/*` (19), `TestDecodeIndependentLiteralFrames/*` (19), `TestDecodeConstructedChangesetRoundTrip` (1); source `object_codec_test.go` / `object_decode_test.go` at the B/C freezes. | [Exact model inventory][fresh-selection], [B integrated model stream][b-log] for encode/hash, [C integrated model stream][c-log], [D model regression stream][d-model-log], [attempt-1 parent stream][fresh-raw]. Actual Encode/Hash and Decode results match literal bytes, typed IDs and decoded fields. The two 19-leaf groups exclude their containers; the singleton is a leaf. |
| C1 | `canopy.local/canopy/tests/conformance`: `TestObjectConformanceLiterals/*` (19) and `TestObjectConformanceSeeded/*` (4), at the exact D source hashes above. | [Accepted independent oracle source][oracle-source], [nonempty oracle audit][oracle-audit], [attempt-1 author confirmation][oracle-confirmation], [D integrated stream][d-log], [attempt-1 parent stream][fresh-raw]. All 23 fixed preimages/digests/TIDs and field inputs agree; product encode/hash/decode is checked in both directions. |
| C2 | Same conformance package: `TestObjectConformanceCompression/{blob_x,root_A_message_ff}` (2), `TestObjectConformanceCompressionAdapterRejects/*` (6). | [Exact criterion cases/stream lines][criteria], [D integrated stream][d-log], [attempt-1 parent stream][fresh-raw]. Distinct bounded fixture encodings converge to the fixed canonical frame and expected typed ID; adapter failures return error and nil data. |
| C2 | Same package: `TestObjectConformanceBlobRejects/*` (13), `TestObjectConformanceChangesetRejects/*` (39), `TestObjectConformanceChangesetFraming/*` (10), `TestObjectConformanceIO/*` (21), `TestObjectConformanceBoundedResources/*` (5). | [Exact criterion cases/stream lines][criteria], [D integrated stream][d-log], [attempt-1 parent stream][fresh-raw], [CORE specificity note][d-core-note]. These 88 leaves plus the 8 compression leaves give 96; looped truncation offsets are not counted as separate leaves. |

C1's independent expectations were inspected in attempt 1: A's [19-row frozen literal table][literal-table] and [oracle receipt][literal-receipt] pin FND-03's standalone `struct`/`hashlib` [generator][f03-generator] and nonempty [original output][f03-vectors]. That original output has **13 digest PASS rows**, not the historical “14” claim. It is not proof for all 19 rows by itself. The accepted D CORE [oracle source][oracle-source] and [audit output][oracle-audit] independently reconstruct all 19 literals plus four seeded cases, use no model methods, and verify provenance and seed recipes. The attempt-1 author directly checked those artifacts, their hashes, all 23 preimages/digests/TIDs, and equality to A's frozen table ([confirmation][oracle-confirmation]); that historical documentary check is not a fresh independent review or additional product test count. Seeds are LCG32 `0xd0100000` through `0xd0100003`.

C1 covers canonical v1 blob/changeset kinds, raw metadata and message bytes, ordered and repeated parents, absent versus present-empty options, distinct regular/executable/symlink tags, and distinct case/Unicode/non-UTF-8 path bytes. It does not establish parent publication or same-repository reachability, final parent-derived tree validity, authorization, or durable storage; those are separate consumers of the codec.

C2's precise alternate-encoding proof uses Go gzip `NoCompression` and `BestCompression` in a **test-only adapter**, only for `blob_x` (23 canonical frame bytes) and `root_A_message_ff` (68 frame bytes). The two representations must differ; each is decompressed with a 4,096-byte compressed-input cap and the exact frame-length expanded cap, compared byte-for-byte with the fixed canonical frame, then decoded against its fixed expected typed ID. This proves the same logical ID for those two representations of each listed frame. It establishes neither a new runtime transport nor product gzip storage/transport support, codec negotiation, production decoder-window/expansion-ratio enforcement, or unbounded capacity. The [canonical contract](../../../api/contracts/canonical.md) keeps storage/RPC envelopes separate; concrete transport enforcement belongs to FND-05/OBJ-04 and their own evidence.

The adapter disables multistream, probes at most one expanded byte beyond its cap, requires one complete member/checksum and no remaining compressed bytes. Its six negatives reject compressed-budget overrun, expansion-budget overrun, truncation, corrupt checksum, a trailing byte and a concatenated second member. No separate invalid-DEFLATE-body case is claimed.

Canonical negatives cover bad magic/version/kind and typed IDs; corrupt payload/message or wrong digest; zero identities; short/long/overflow lengths, remaining-byte/count and field maxima; invalid presence markers/offsets; wrong parent/target kinds, unknown tags, missing SET targets or DELETE targets; invalid/duplicate/unsorted paths and conflicting SET ancestors; trailing payload/frame bytes; caller budgets and every strict truncation of the tested frames. Only the **39 `TestObjectConformanceChangesetRejects` syntax-table cases** carry independently recomputed matching digests to isolate malformed changeset syntax rejection. Four `TestObjectConformanceChangesetFraming` header cases (`magic`, `unknown_version`, `unknown_kind`, `kind_identity_mismatch`) retain the original `root_A_message_ff` expected ID; they do not independently isolate syntax rejection from digest mismatch ([original security finding][prior-security]). Framing/corruption evidence remains distinct. Failures return an error and a zero changeset or zero successful blob length. Blob writes remain **unverified private staging until success** and must be discarded on error; the tests do not promise rollback of staging writes. I/O errors with data, invalid reader counts, short/failing writes, cancellation and 100-call no-progress termination are exercised.

**Approved D CORE note retained:** malformed blob header/length cases reuse the original `blob_x` expected ID. Those individual assertions do not independently isolate syntax rejection from digest mismatch. CORE inspected header validation before payload processing and rehashed early-rejection resource probes, accepted fail-closed behavior, and marked improved syntax isolation as nonblocking future work ([exact review][d-core], [detailed note][d-core-note]). No stronger blob syntax-isolation claim is made here.

I20 evidence is bounded: D streams 65,553 payload bytes with observed reader/writer calls at most 32 KiB; rehashed format/caller-limit probes reject after the 22-byte header without payload output. B/C also test declared maxima and preallocation guards. Header-only probes and canceled maximum declarations are not full 1 TiB transfers, 64 MiB changeset capacity tests, memory/RSS measurements, fuzz campaigns, CPU/queue overload qualification, or scale results. The unmeasured portions of I20 remain required beyond this codec evidence.

**Historical attempt-1 local verification.** Executed once on unchanged predecessor code `2181e878956c91de50aaa15a6c91ff68389afeca`, 2026-10-15 11:44:14–11:44:17 UTC, Darwin/arm64, pinned Go 1.27.2; this command was not rerun for attempt 2:

```text
/Users/completetech/github/.scion-run/toolchains/go/bin/go test -json -count=1 -trimpath -buildvcs=false -shuffle=off -parallel=1 -timeout=120s ./internal/model ./tests/conformance
```

[Historical command/result][fresh-result], [raw stdout][fresh-raw], [selected events][fresh-events] and [selection validation][fresh-selection] record exit 0, 173 model leaves plus 119 conformance leaves (C1 23/C2 96), 22 separate parent containers and two package pass terminals. Every selected leaf ran and passed exactly once; no failure, skip, missing or duplicate leaf. These are prior supporting evidence on `2181e878956c91de50aaa15a6c91ff68389afeca`, not product verification of prior document candidate `ccc48fc554fcf7a1c5f85896565329397d9ec746`, this attempt-2 successor, or its integration. These focused counts overlap prior child runs and are not additive qualification totals.

The historical [environment policy][fresh-env] used fresh attempt-1-specific `GOCACHE`, `GOMODCACHE`, `GOPATH` and `GOTMPDIR`; `GOENV=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOVCS=*:off GOWORK=off`, with empty `GOFLAGS`. Inherited `HOME=/Users/completetech` was preserved; `home` and `CODEX_HOME` stayed unset. No download/install occurred. [Before/after source pins][fresh-before] and [after pins][fresh-after] matched, as did [Go binary pins before][tool-before] and [after][tool-after]. Empty stderr is represented by the nonempty [stream index][streams], not by an empty file as sole proof. Go offline settings do not assert OS network isolation.

**Historical attempt-2 documentary verification, author-stage snapshot at `2026-10-15T13:04:21.855575+00:00`.** [First-read record][first-read2], [exact prior-byte restoration][restoration2], [pinned historical source copies][historical-pins2] and [fresh documentary claim/identity checks][documentary2] bound the original author-stage wording repair to the frozen inputs, full verbatim C1/C2, exact model/conformance identities, source lines and review findings. These are documentary assertions with zero product tests; no Go suite was rerun. Historical failures and original evidence remain preserved. An exact prepared-document byte freeze is a host-commit handoff, not a candidate commit, independent review, integration execution or acceptance.

Historical full/build verification remains attached to each accepted integration, not rerun or attributed to this document candidate. D's accepted integration has 614 full behavior leaves plus three separate helpers and an eight-package build; A/B/C retain their own distinct integrated checks. Earlier failures remain evidence: [B v4 startup failure][b-failure] (`NOT_READY`, exit 2), C's [compile][c-failure1], [pin-preflight][c-failure2], [oracle-fixture][c-failure3], and [report-count][c-failure4] failures, and D's [initial Git handoff failure][d-git-failure] and [no-suite preflight failure][d-preflight-failure]. None is relabeled as a pass or counted as product verification.

**Requirements, invariants and gates remain in scope.** [R02/R03][requirements] are required: R02 receives local typed immutable canonical codec evidence; R03 receives logical identity/compression-envelope conformance evidence only. Compressed durable content-addressed storage, authorized delivery, restart/crash durability, production transport and qualification still require their own accepted implementations and evidence. No scope ledger is edited or blocked requirement converted to optional.

[I15/I16/I20][invariants] apply without dilution: I15 requires director-owned submission/review/integration/acceptance; attempt-1 submission is history; at the historical author-stage snapshot at `2026-10-15T13:04:21.855575+00:00`, successor submission, fresh reviews, integration, integration verification and acceptance were pending. Subsequent/current status is determined by director records. I16 restricts these local results to local claims; I20 receives the specific bounds above and retains untested resource dimensions. FND-07 harness acceptance is not proof of board authorization, cloud behavior, or product resource qualification.

All [G0–G8 milestones][gates] and their [original task criteria][gate-tasks] remain applicable in their original scope; this document casts no gate verdict. The imported task identifies G1 as the earliest transitively requiring gate; G8 explicitly requires OBJ-01. Local codec evidence alone does not satisfy either gate.

| Gate | Preserved scope |
|---|---|
| G0 | Approve foundation and execution contracts. |
| G1 | Accept durable publish/read slice, including two authenticated processes and restart evidence. |
| G2 | Accept useful sparse and API edit slice. |
| G3 | Accept graph/query/edit completeness. |
| G4 | Accept cache and real virtual workspace, including real writable Linux mount evidence. |
| G5 | Accept review/search/CI ecosystem. |
| G6 | Accept migration and complete local product. |
| G7 | Accept real cloud-backed behavior with separate real-cloud evidence. |
| G8 | Full-scope qualification and final audit; unfinished/blocked capabilities remain explicit. |

Historical author-stage status separation at `2026-10-15T13:04:21.855575+00:00`: `implemented` = inherited accepted A–C codec primitives and D conformance fixtures, plus this repaired acceptance document; `verified-local` = the exact scoped historical product evidence above and separate attempt-2 documentary checks, with no attempt-2 product execution; `verified-cloud` = not established; `verified-scale` = not established. **Attempt-1 host-commit instruction is history:** root locally committed and submitted `ccc48fc554fcf7a1c5f85896565329397d9ec746`; its reviews required this repair. At that historical author-stage snapshot at `2026-10-15T13:04:21.855575+00:00`, the attempt-2 successor was uncommitted, and root host commit, separately requested committed-candidate documentary binding, two fresh independent exact-candidate Sol reviews (one CORE), integration of the reviewed SHA, criterion-level integration verification and acceptance were pending. As of that snapshot, this author had not staged, committed, merged, pushed, published, written the board, voted or self-accepted. Subsequent and current commit, board submission, review, integration and acceptance status are determined by director records.

[task]: /Users/completetech/github/.scion-run/operations/github-issue-import-20261015/bodies/OBJ-01.md
[packet]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/packet.json
[pins]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/launch/input-pins.json
[inputs]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/input-verification.json
[history]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/historical-evidence.json
[sources]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/source-identity-audit.json
[historical-tests]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/historical-test-identities.json
[reference-audit]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/dependency-reference-audit.json
[criteria]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/criterion-evidence.json
[f03]: /Users/completetech/github/.scion-run/evidence/FND-03/attempt-2/acceptance.json
[f03-source]: /Users/completetech/github/.scion-run/evidence/FND-03/attempt-2/submission.json
[f03-core]: /Users/completetech/github/.scion-run/evidence/FND-03/attempt-2/core-review.json
[f03-sec]: /Users/completetech/github/.scion-run/evidence/FND-03/attempt-2/security-review.json
[f03-int]: /Users/completetech/github/.scion-run/evidence/FND-03/attempt-2/integration.json
[f03-log]: /Users/completetech/github/.scion-run/evidence/FND-03/attempt-2/integration.log
[f03-generator]: /Users/completetech/github/.scion-run/evidence/FND-03/attempt-2/canonical-vectors-independent.py
[f03-vectors]: /Users/completetech/github/.scion-run/evidence/FND-03/attempt-2/vector-run.txt
[f07]: /Users/completetech/github/.scion-run/evidence/FND-07/attempt-2/acceptance.json
[f07-source]: /Users/completetech/github/.scion-run/evidence/FND-07/attempt-2/prepared-source.json
[f07-core]: /Users/completetech/github/.scion-run/evidence/FND-07/attempt-2/core-review.json
[f07-int]: /Users/completetech/github/.scion-run/evidence/FND-07/attempt-2/integration.json
[a]: /Users/completetech/github/.scion-run/evidence/OBJ-01-A/attempt-1/acceptance.json
[a-source]: /Users/completetech/github/.scion-run/evidence/OBJ-01-A/attempt-1/candidate-source-freeze.json
[a-core]: /Users/completetech/github/.scion-run/evidence/OBJ-01-A/attempt-1/core-review.json
[a-sec]: /Users/completetech/github/.scion-run/evidence/OBJ-01-A/attempt-1/security-review.json
[a-int]: /Users/completetech/github/.scion-run/evidence/OBJ-01-A/attempt-1/integration.json
[a-log]: /Users/completetech/github/.scion-run/evidence/OBJ-01-A/attempt-1/integration-native-20261015T0600/checks/commands/focused.stdout.raw
[literal-table]: /Users/completetech/github/.scion-run/evidence/OBJ-01-A/attempt-1/frozen-vector-source.json
[literal-receipt]: /Users/completetech/github/.scion-run/evidence/OBJ-01-A/attempt-1/independent-vector-receipt.json
[b]: /Users/completetech/github/.scion-run/evidence/OBJ-01-B/attempt-1/acceptance.json
[b-source]: /Users/completetech/github/.scion-run/evidence/OBJ-01-B/attempt-1/candidate-source-freeze.json
[b-core]: /Users/completetech/github/.scion-run/evidence/OBJ-01-B/attempt-1/core-review.json
[b-sec]: /Users/completetech/github/.scion-run/evidence/OBJ-01-B/attempt-1/security-review.json
[b-int]: /Users/completetech/github/.scion-run/evidence/OBJ-01-B/attempt-1/integration.json
[b-log]: /Users/completetech/github/.scion-run/evidence/OBJ-01-B/attempt-1/integration-v6-obj01b-20261015t0818z/commands/focused/run.stdout.log
[b-failure]: /Users/completetech/github/.scion-run/operations/obj01b-integration-v4/20261015t0802z/actual-run-execution.json
[c]: /Users/completetech/github/.scion-run/evidence/OBJ-01-C/attempt-1/acceptance.json
[c-source]: /Users/completetech/github/.scion-run/evidence/OBJ-01-C/attempt-1/source-freeze-v3.json
[c-core]: /Users/completetech/github/.scion-run/evidence/OBJ-01-C/attempt-1/core-review.json
[c-sec]: /Users/completetech/github/.scion-run/evidence/OBJ-01-C/attempt-1/security-review.json
[c-int]: /Users/completetech/github/.scion-run/evidence/OBJ-01-C/attempt-1/integration.json
[c-log]: /Users/completetech/github/.scion-run/evidence/OBJ-01-C/attempt-1/integration-v7-obj01c-20261015t0838z/commands/focused/run.stdout.log
[c-failure1]: /Users/completetech/github/.scion-run/evidence/OBJ-01-C/attempt-1/failure-analysis-1.json
[c-failure2]: /Users/completetech/github/.scion-run/evidence/OBJ-01-C/attempt-1/failure-analysis-2.json
[c-failure3]: /Users/completetech/github/.scion-run/evidence/OBJ-01-C/attempt-1/failure-analysis-3.json
[c-failure4]: /Users/completetech/github/.scion-run/evidence/OBJ-01-C/attempt-1/failure-analysis-4.json
[d]: /Users/completetech/github/.scion-run/evidence/OBJ-01-D/attempt-1/acceptance.json
[d-source]: /Users/completetech/github/.scion-run/evidence/OBJ-01-D/attempt-1/candidate-source/tests/conformance/object_codec_test.go
[d-binding]: /Users/completetech/github/.scion-run/evidence/OBJ-01-D/attempt-1/postcommit-verification-ec97b3a40d3a/handoff.json
[d-core]: /Users/completetech/github/.scion-run/evidence/OBJ-01-D/attempt-1/core-review-independent-2/core-review-actor-corrected.json
[d-core-note]: /Users/completetech/github/.scion-run/evidence/OBJ-01-D/attempt-1/core-review-independent-2/c2-notes.md
[d-sec]: /Users/completetech/github/.scion-run/evidence/OBJ-01-D/attempt-1/security-review.json
[d-int]: /Users/completetech/github/.scion-run/evidence/OBJ-01-D/attempt-1/integration.json
[d-log]: /Users/completetech/github/.scion-run/evidence/OBJ-01-D/attempt-1/integration-after-iam10-serial-v2-20261015t1119z/commands/focused-conformance/run.stdout.log
[d-criteria]: /Users/completetech/github/.scion-run/evidence/OBJ-01-D/attempt-1/criterion-evidence.json
[d-git-failure]: /Users/completetech/github/.scion-run/evidence/OBJ-01-D/attempt-1/commands/authorized-git-add/result.json
[d-preflight-failure]: /Users/completetech/github/.scion-run/operations/serial-obj01d-after-iam10-20261015t1130z/preflight/receipt.json
[oracle-source]: /Users/completetech/github/.scion-run/evidence/OBJ-01-D/attempt-1/core-review-independent-2/oracle_audit.py
[oracle-audit]: /Users/completetech/github/.scion-run/evidence/OBJ-01-D/attempt-1/core-review-independent-2/oracle-audit.json
[oracle-confirmation]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/oracle-confirmation.json
[fresh-result]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/local-verification/result.json
[fresh-raw]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/local-verification/stdout.raw
[fresh-events]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/local-verification/selected-events.json
[fresh-selection]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/local-verification/selection-validation.json
[fresh-env]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/local-verification/environment-policy.json
[fresh-before]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/local-verification/source-before.json
[fresh-after]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/local-verification/source-after.json
[tool-before]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/local-verification/tool-before.json
[tool-after]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/local-verification/tool-after.json
[streams]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-1/author-sol-codec-accept1/local-verification/stream-index.json
[requirements]: /Users/completetech/github/prompts/scion-agent-prompt-package/tracking/requirements.json
[invariants]: /Users/completetech/github/prompts/scion-agent-prompt-package/references/03_INVARIANTS.md
[gates]: /Users/completetech/github/prompts/scion-agent-prompt-package/tracking/milestones.json
[gate-tasks]: /Users/completetech/github/prompts/scion-agent-prompt-package/tracking/tasks.json
[prior-core]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-2/author-sol-codec-accept2/inputs/repair/core-review.json
[prior-security]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-2/author-sol-codec-accept2/inputs/repair/security-review.json
[review-collection]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-2/author-sol-codec-accept2/inputs/repair/root-review-collection-001.json
[prior-stopped]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-2/author-sol-codec-accept2/inputs/repair/root-stopped-writer-001.json
[packet2]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-2/author-sol-codec-accept2/inputs/packet.json
[pins2]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-2/author-sol-codec-accept2/inputs/input-pins.json
[pins2-verified]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-2/author-sol-codec-accept2/pin-verification.json
[digest-reconciliation]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-2/author-sol-codec-accept2/inputs/repair/review-dispatch-contract-reconciliation-001.json
[d-model-log]: /Users/completetech/github/.scion-run/evidence/OBJ-01-D/attempt-1/integration-after-iam10-serial-v2-20261015t1119z/commands/focused-model-regression/run.stdout.log
[first-read2]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-2/author-sol-codec-accept2/first-read.json
[restoration2]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-2/author-sol-codec-accept2/restoration.json
[historical-pins2]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-2/author-sol-codec-accept2/historical-source-pins.json
[documentary2]: /Users/completetech/github/.scion-run/evidence/OBJ-01/attempt-2/author-sol-codec-accept2/documentary-verification.json
