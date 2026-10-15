# Native qualification plan — proposal awaiting ratification

FND-11 attempt 1 addresses R47, C1 (reproducible profiles, numerical hypotheses, hardware and budgets) and C2 (visible owner and capacity blockers). This is a **proposal**, not measured results, approved production targets, or permission to provision infrastructure. Every proposed number in this document, including dataset sizes, mixes, seeds, limits, schedules, hardware, SLOs and USD amounts, is **UNAPPROVED**. Identifiers, source versions/hashes and observations explicitly attributed to evidence are provenance, not proposed targets. Existing contract limits are constraints, not newly approved capacity claims.

## Provenance and present boundary

| Input | Pinned identity |
|---|---|
| Dispatch | `evidence/FND-11/attempt-1/packet.json`; actor `sol-herdr-qualification`; branch `work/FND-11/attempt-1` |
| Base and accepted dependency | `cd7c35e6a64c5fcdfbd7b5ec2a2ea81e7c5c3e0c`; FND-02 attempt 3, `evidence/FND-02/attempt-3/acceptance.json` |
| Packet contract bundle SHA-256 | `0261c136704e7b4b7621fd871895bea13dc669eabc9bbaf67bf9be089a1977ed` |
| Package service catalog SHA-256 | `9b058e21b28263db98f9bfbf9e5661ba98517aef2d369c61ae501dd2d6fcaaf0` |
| `api/contracts/canonical.md` SHA-256 | `eceab23e153e7d96558858ef76448d41b34bf844315b5d37cea4f0404df4b9c2` |
| `api/contracts/security.md` SHA-256 | `ed748131108d155d578b8e4d72c7977a63ce0c1c8ab248db3055eb5933745a1e` |

The bundle is the packet's sorted path/length/content hash, verified before editing. The packet defines this task's input snapshot; it does not remove pending product, wire, codec or security ratification gates described by those inputs. This plan does not amend them.

Read with the package's `references/03_INVARIANTS.md`, `references/04_CONTRACTS_AND_DATA.md`, `references/10_VALIDATION_AND_BENCHMARKS.md` and `contracts/service_catalog.json`, plus the accepted `docs/decisions/runtime_matrix.md`. Service names below come from that proposed inventory; naming an operation does not assert it exists. These are original engineering proposals, not unpublished Anthropic internals or source-article speedups.

The accepted runtime evidence establishes a macOS Apple Silicon worker, Go 1.27.2, explicitly selected Homebrew Python 3.14.4, Node 24.15.0, and a historically ready Linux/aarch64 Docker engine. It does not establish real Linux FUSE, PostgreSQL, Spanner, Cloud Storage, emulator conformance, cloud credentials, or measured scale capacity. FND-11 preflight observed Git 2.54.0, 14 logical CPUs, 36 GiB RAM and approximately 107 GiB free disk on this worker. Those observations do not qualify it for the medium or scaled profiles. The dispatch's Sol/ultra/ultrafast setting supersedes the historical Luna worker observation; no session settings are changed here.

| Claim dimension | Current state |
|---|---|
| implemented | Documentation proposal only; no benchmark runner or product implementation supplied by FND-11 |
| verified-local | Document structure, arithmetic, provenance and scope can be checked locally; no performance or product behavior established |
| verified-cloud | NOT VERIFIED; no cloud tests or spend authorized |
| verified-scale | NOT VERIFIED; no measured fleet capacity, throughput or qualification result |

## Workload profiles (all quantities UNAPPROVED)

Counts are per primary repository unless marked fleet-wide. Every profile also has a small isolation repository with 32 leaves and 16 changesets, separate identities and overlapping blob content; it is excluded from primary counts but included in storage and cost accounting. Qualification has eight primary repositories; other profiles have one. Histories include bootstrap commits, not just timed writes. Loading uses an empty root followed by batches of at most 4,096 path operations and at most 1 MiB canonical changeset payload; never put a million-file root in a single changeset.

| Profile | Primary repos | Leaves/repo | Changesets/repo | Longest first-parent spine | Widest directory | Maximum path components | Post-bootstrap single/two/four-parent % | Hardware | Status |
|---|---:|---:|---:|---:|---:|---:|---|---|---|
| smoke | 1 | 512 | 64 | 48 | 128 | 8 | 90/10/0 | local | UNAPPROVED |
| correctness | 1 | 4096 | 8192 | 4096 | 2048 | 64 | 70/25/5 | local | UNAPPROVED |
| medium | 1 | 100000 | 100000 | 50000 | 50000 | 128 | 85/14/1 | medium | UNAPPROVED |
| qualification | 8 | 1000000 | 1000000 | 500000 | 500000 | 256 | 80/18/2 | scaled | UNAPPROVED |

The spine advances deterministically; side branches fork from retained spine checkpoints, then reconverge. Two-parent merge slots contain repeated criss-cross motifs with multiple best common ancestors; four-parent slots exercise ordered octopus ancestry. The first parent supplies the tree base; other parents never imply a union. Generated merges alternate disjoint edits and intentional same-line/delete-modify conflicts. Conflicts have explicit oracle outcomes and are not counted as successful edits. Smoke uses a separate fixed criss-cross fixture if rounding leaves insufficient merge slots. Correctness additionally exercises repeated parent IDs, reversed parent order and zero-parent roots as separately identified vectors.

| Profile | ASCII / byte-edge paths % | Regular / executable / symlink leaves % | Update / add / delete / mode-only operations % | Intentional conflicting merge slots % | Post-bootstrap paths changed/node | Status |
|---|---|---|---|---:|---:|---|
| smoke | 98/2 | 90/8/2 | 70/10/10/10 | 25 | 4 | UNAPPROVED |
| correctness | 80/20 | 80/10/10 | 50/15/15/20 | 50 | 8 | UNAPPROVED |
| medium | 95/5 | 94/5/1 | 70/10/10/10 | 25 | 8 | UNAPPROVED |
| qualification | 95/5 | 94/5/1 | 70/10/10/10 | 25 | 8 | UNAPPROVED |

Byte-edge paths include literal `ff`, NFC/NFD pairs, case pairs, backslash and percent spellings. Depth and width stress fixtures are deliberately distinct from these byte-edge names. On a host that cannot represent them, API/byte-oracle checks remain required; materialization must return a collision/unsupported result before writes. It cannot silently normalize or skip fixtures. Native mode tags preserve `100644`, `100755`, `120000`; symlink payloads are literal link bytes and are never followed during generation. Negative fixtures include traversal/NUL/duplicate/out-of-order paths, prefix-conflicting leaves, unsafe links, directory-to-file transitions and dirty checkout protection.

Initial regular/executable payloads by object count are 70% 4 KiB, 25% 64 KiB, 4% 1 MiB and 1% 8 MiB. Symlink payloads are 32 bytes. Half the regular payloads are deterministic line-oriented text; half are deterministic high-entropy binary. Post-bootstrap new content is 4 KiB, with 25% exact-blob reuse by SET count and 75% new bytes; these are generation settings, not cache-hit claims. Pair add/delete slots so the advertised checkpoint leaf count is exact. Mode-only edits reference unchanged blobs. Retain intermediate trees for history checks. Logical historical payload ceilings are 2 GiB (local), 100 GiB (medium), and 4 TiB (scaled fleet); crossing one blocks the run pending a revised manifest, never truncates the dataset silently. Report actual unique bytes, logical referenced bytes and physical bytes separately.

V1 admits only blobs and changesets; derived tree pages are not a newly invented canonical kind. Respect its 64 MiB changeset, 1,000,000-operation and 1,024-parent maxima and checked byte/path bounds. Use bounded pages and persistent structural sharing for wide directories. Gitlinks/submodules, empty-directory inputs and unresolved fidelity cases go into a durable unsupported-input manifest and block that migration claim. LFS pointers remain literal bytes. Preserve original Git bytes and source/native mappings; native identity need not equal a Git object ID. Larger contract-boundary fixtures run as correctness cases, not as hidden exclusions from performance populations.

## Deterministic generation and separate caller traces

The proposed generator version is `qualification-v1`; it is a specification for future work, not an implemented script. Use base seed `4701101`, independently repeated seeds `4701102` and `4701103`. Derive each stream from SHA-256 of UTF-8 `qualification-v1|seed|profile|repo-index|stream-name|counter`; counters are unsigned decimal with no leading zeroes, and domain fields contain no `|`. Byte blocks append a block counter to that domain. Sort SHA-256 ranks, breaking ties by original index, to allocate exact quotas by largest remainder (ties by listed category order). Store the chosen integer quotas so rounding cannot vary by language. Never use wall-clock timestamps, language-default PRNGs, or scheduler order as fixture identity.

Allocate the fixed spine and bootstrap first. Rank the remaining eligible node slots into parent-count quotas; allocate side-branch nodes before their dependent merge slots, then topologically number the final DAG with deterministic index tie-breaking. Build each criss-cross motif as paired branches with alternating first parents and explicit merge bases; if the requested graph cannot fit all quotas/depth/width constraints, generation fails before execution. Record full parent lists, operation lists, file byte digests, tree oracle digests, source/native mappings and a manifest hash. Set author time to a fixed epoch plus node index, retain explicit offsets and byte metadata, and hash the final canonical bytes. No retry regenerates content under another identity.

Generate JSONL event traces before either system runs. Candidate event count is session count × offered events/second × repetition seconds; assign operations and read/write quotas by the same rank/largest-remainder rule. For each session and second, rank its event offsets from hash integers modulo 1,000,000 microseconds, breaking ties by event index. Each event records sequence, scheduled offset, caller class, repository, session ID, operation and parameters, payload digest/size, expected result class, dependency event IDs, idempotency key, deadline and source/policy/index versions. Trace generation serially assigns each session's base revision and expected dependency results; runtime interleaving cannot alter the input trace. Credentials are injected by a protected fixture setup and never stored in traces. Outcome records capture real start/end and queue wait. Public artifacts use opaque fixture labels; restricted evidence holds byte paths and protected identities. A manifest pins generator source SHA, plan SHA, contract bundle, all seeds, trace hashes and independent oracle version. Until that executable generator and its conformance vectors exist, reproducible *execution* remains blocked.

| Caller trace | Read mix within reads (sum 100%) | Write mix within writes (sum 100%) | Behavior | Status |
|---|---|---|---|---|
| developer | GetObjects 40; GetRootView 15; Diff 15; PathHistory 10; Blame 5; SearchContent 10; GetRef 5 | CreateChangeset 50; CompareAndSwapRef 20; Merge 10; CreateChangeRequest 10; AddPatchset 10 | Interactive sequence, 250 ms think time after dependency completion, stable workspace; upload required blobs before publishing | UNAPPROVED |
| agent | GetObjects 25; GetRootView 15; Diff 15; IsAncestor 10; MergeBases 10; SearchContent 20; GetChangeset 5 | ApplyPathEdits 60; CreateChangeset 20; AddPatchset 10; CompareAndSwapRef 10 | Bursts of 8 bounded reads, then one dependent edit batch; 50 ms between bursts, isolated session and detached work | UNAPPROVED |
| CI | GetObjects 65; GetRootView 10; Diff 10; IsAncestor 5; GetChangeset 5; SearchPaths 5 | ScheduleValidation 40; RecordValidation 40; CompareAndSwapRef 20 | Fresh job identity/workspace per batch, exact revision and policy, no think time; separate job/cold-start and steady-state distributions | UNAPPROVED |

One CreateChangeset/ApplyPathEdits logical write includes its prerequisite BeginUpload/UploadChunks/FinishUpload calls in end-to-end timing and cost; RPC metrics also separate each stage. Each workload's read/write split below is by logical top-level events, not by constituent RPCs or byte volume. Emit independent developer, agent and CI files and separate metrics even during a mixed run. Caller counts describe active sessions; they do not multiply per-host queue limits.

| Profile | Developer/agent/CI sessions | Fleet sessions | Developer read/write % | Agent read/write % | CI read/write % | Arrival events/s per session | Warmups | Measured repetitions | Measured seconds/repetition | Cadence | Status |
|---|---|---:|---|---|---|---:|---:|---:|---:|---|---|
| smoke | 1/1/1 | 3 | 80/20 | 70/30 | 95/5 | 2 | 1 | 3 | 5 | Every integration after prerequisite checks | UNAPPROVED |
| correctness | 2/2/2 | 6 | 60/40 | 50/50 | 80/20 | 5 | 1 | 3 | 30 | Nightly and contract/security milestones | UNAPPROVED |
| medium | 8/16/8 | 32 | 80/20 | 70/30 | 95/5 | 10 | 1 | 3 | 60 | Weekly and algorithm/cache changes | UNAPPROVED |
| qualification | 64/128/64 | 256 | 80/20 | 70/30 | 95/5 | 10 | 1 | 3 | 60 | Owner-approved release campaign only | UNAPPROVED |

Arrivals are open-loop at the listed aggregate upper offer rate, with deterministic within-second jitter from the caller stream. Dependencies and think times may reduce actual offers; retain scheduled, issued and dropped counts and never call the upper bound achieved throughput. Queueing is included from scheduled arrival, preventing coordinated omission. Run isolated caller classes and a mixed composition separately. For each system/profile there are 6 cache cases × 4 compositions (developer, agent, CI, mixed) × (1 untimed warmup + 3 measured repetitions). Each repetition uses its own listed seed; warmup uses the base seed. An untimed warmup lasts one repetition duration, is never pooled into measured latency and still consumes wall time/cost.

## Cache cases and controlled failure lanes (all settings UNAPPROVED)

| Case | Initial state and trace selection | Required observation |
|---|---|---|
| cold | New empty node/regional caches and workspace, processes restarted; no snapshot. Authority dataset is preloaded. Empty filesystem cache on isolated Linux host or record inability to clear it. | Include connection/authentication and first-read latency. Never label a warm authority page cache as disk-cold. Reset after warmup and before every measured repetition. |
| snapshot-warm | Load the same hashed, audience-scoped snapshot containing a ranked 20% of requested unique bytes. New process/workspace; OS cache state matched between systems. | Time and charge snapshot build, transfer, verification and activation separately; revalidate current policy on every subsequent read. |
| ordinary-warm | One full same-composition priming trace at fixed capacity, then measurement without resetting; no snapshot. | Record occupancy, eviction and priming expense; no preloaded objects outside the trace. |
| hotset | 90% of requests choose the ranked 10% of eligible objects, uniformly within each group. Prime that hotset only. | Publish achieved object and byte reuse separately for each caller and tier. |
| low-reuse | Uniform stream without replacement until exhausted; working set at least 4 times aggregate node cache byte capacity. No priming. | Generate enough unique content or mark the case blocked; never wrap a small dataset and call it low-reuse. |
| churn | Begin ordinary-warm; every 10 seconds replace ranked 10% of hot objects with new content and rotate 10% of fixture policies. | Count invalidations, stale-grant denials, eviction, index catch-up and new bytes; preserve old versions for the oracle. |

For smoke/correctness reduce the dedicated case cache to at most one quarter of eligible unique bytes so low-reuse is meaningful; the hardware cache maxima below are upper bounds, not minimum occupancy. Snapshot size is not a hit ratio. Restore each repetition's authority dataset and case-specific cache image independently. For ordinary-warm/churn, the warmup trace supplies the primed image cloned before each measured repetition; record that image's hash and charge its creation once per run. For hotset, prime only its prescribed hotset; cold resets after warmup; snapshot-warm reloads the same selected snapshot. Git snapshot-warm uses a measured, equivalently selected preseeded object cache/bundle; if equivalence is not possible, report the pair non-comparable rather than comparing preloaded native data to an empty Git clone.

Run correctness/fault lanes separately from healthy throughput lanes: acknowledged-write crash/restart, lost response/retry, corrupt/truncated object, partial snapshot, region isolation, delayed invalidation, cache miss storm and authority loss. Never bypass an unhealthy node/regional tier to flood authority. Observe typed failure and bounded retries. Fault time remains in failure-lane denominators; do not silently discard it from a claimed healthy result.

## Named-operation SLO hypotheses (UNAPPROVED)

These are falsifiable investigation thresholds, not a production promise. They apply to valid authorized requests in ordinary-warm state at the stated profile concurrency on its matched hardware. Durations include client scheduling/queue wait, network, auth and integrity verification through final byte/durable acknowledgement. Cold/snapshot/churn results must be reported separately with the same metrics; no warm threshold is retroactively claimed for them. Different payloads/depths get distinct histograms. A hypothesis failure remains visible even if the run completes.

| ID | Named operation and bounded payload | Profiles | p50 ms | p95 ms | p99 ms | Completed logical ops/s floor | Status |
|---|---|---|---:|---:|---:|---:|---|
| S1 | ObjectService.GetObjects; 1 blob, 4 KiB verified payload | smoke, correctness | 5 | 20 | 50 | 2 | UNAPPROVED |
| S2 | ObjectService.GetObjects; 1 blob, 4 KiB verified payload | medium | 10 | 40 | 100 | 100 | UNAPPROVED |
| S3 | ObjectService.GetObjects; 1 blob, 4 KiB verified payload | qualification | 20 | 75 | 200 | 800 | UNAPPROVED |
| S4 | ObjectService.GetObjects; 1 blob, 1 MiB verified payload | medium, qualification | 40 | 150 | 400 | 40 | UNAPPROVED |
| S5 | ChangesetService.CreateChangeset plus upload; 8 SETs, 32 KiB new blobs, at most 16 KiB metadata | medium | 50 | 150 | 400 | 20 | UNAPPROVED |
| S6 | ChangesetService.CreateChangeset plus upload; 8 SETs, 32 KiB new blobs, at most 16 KiB metadata | qualification | 100 | 300 | 800 | 200 | UNAPPROVED |
| S7 | QueryService.GetRootView; 1 directory page, 256 entries, at most 64 KiB response | medium, qualification | 20 | 80 | 200 | 40 | UNAPPROVED |
| S8 | QueryService.Diff; 8 changed paths, 32 KiB input bytes, at most 64 KiB response | medium, qualification | 50 | 200 | 500 | 20 | UNAPPROVED |
| S9 | QueryService.IsAncestor; 2 IDs, 100000-node history, at most 4096 traversed nodes/query | medium | 20 | 100 | 300 | 20 | UNAPPROVED |
| S10 | QueryService.MergeBases; 2 IDs, 1000000-node history, at most 65536 traversed nodes and 16 returned bases | qualification | 100 | 500 | 1500 | 10 | UNAPPROVED |
| S11 | RefService.CompareAndSwapRef; 1 alias at most 128 bytes, target and generation, uncontended | medium, qualification | 20 | 75 | 200 | 10 | UNAPPROVED |
| S12 | MigrationService.ImportStream; 1000 source changesets/batch, 32 MiB logical source input | medium, qualification | 1000 | 3000 | 8000 | 0.125 | UNAPPROVED |

S12's throughput floor is batches/s (also report changesets/s and MiB/s). For other rows, ops/s counts completed logical requests, not uploaded chunks. Execute each SLO row in a separately labeled calibration lane at an offered rate of 1.25 times its floor; do not require every floor simultaneously from the mixed trace. Qualification's S3/S6 floors are fleet-wide, while latency is per request with per-repository and per-host breakouts. S9/S10 must return a typed budget exhaustion when traversal would exceed the bound, never a fabricated answer; these failures do not meet the completion floor. Competing CAS/landing has a separate fairness lane, expected conflicts, retry counts and starvation reports, not S11's uncontended success population.

| Resource or completion hypothesis | local | medium | scaled fleet | Status |
|---|---:|---:|---:|---|
| GetObjects 4 KiB total service/client CPU-seconds per successful logical op | 0.02 | 0.03 | 0.05 | UNAPPROVED |
| CreateChangeset 8 SET / 32 KiB CPU-seconds per success, including upload | 0.20 | 0.30 | 0.50 | UNAPPROVED |
| Per service host steady RSS ceiling GiB | 6 | 24 | 48 | UNAPPROVED |
| Per service host peak RSS ceiling GiB | 8 | 32 | 64 | UNAPPROVED |
| Per node daemon persistent cache ceiling GiB | 0.125 | 2 | 8 | UNAPPROVED |
| Fleet queued requests ceiling (reject beyond, preserve counts) | 96 | 1024 | 8192 | UNAPPROVED |
| Derived index visibility lag p95 seconds | 1 | 2 | 5 | UNAPPROVED |
| Derived index visibility lag p99 seconds | 3 | 5 | 15 | UNAPPROVED |
| Healthy-lane unexpected failure fraction ceiling | 0.001 | 0.001 | 0.001 | UNAPPROVED |

Safety requirements have no error budget: corruption, unauthorized bytes, lost acknowledged data or wrong oracle answers invalidate performance claims. Expected conflicts/denials remain separately counted; they do not improve success throughput. CPU totals include supporting database/cache processes and both load generator and servers, with each component also broken out. End-to-end upload amplification, network bytes and disk usage are measured even when no numerical SLO is yet ratified.

## Required hardware, network and storage (UNAPPROVED)

Hardware below is a requested experiment configuration, not an inventory of allocated machines. Pin CPU model/architecture, cores versus threads, RAM, OS/kernel, filesystem/mount options, database/version, codecs, service binary SHA and all runtime flags. Fix power mode, avoid shared tenants, record throttling/steal, and keep load-generator saturation visible. Native/Git A/B uses the same allocations sequentially, with independent resettable volumes; no concurrent benchmark competes for the same hardware.

| Profile ID | Compute and roles | RAM | Persistent storage requirement | Network requirement | Capability state | Status |
|---|---|---|---|---|---|---|
| local | 1 host, at least 8 dedicated cores; cap services 4 cores and load generator 2 cores; macOS documentation/API lanes or isolated Linux host for OS lanes | 16 GiB minimum | 20 GiB free scratch on SSD; at least 250 MiB/s sequential and 5000 random 4 KiB IOPS; dataset/cache/evidence quotas enforced separately | Loopback primary lane; separate emulated 1 Gbit/s, 1 ms RTT lane with loss 0%; record shaper settings | Current host has enough nominal RAM/free bytes; dedicated cores, storage speed and Linux FUSE NOT VERIFIED | UNAPPROVED |
| medium | 2 Linux hosts: 1 service host with 16 dedicated cores for durable authority, regional/node tiers; 1 load/Git-client host with 8 dedicated cores | Service 64 GiB; client 32 GiB | Service 1 TiB NVMe, client 512 GiB SSD; 1 GiB/s sequential, 50000 random 4 KiB IOPS service; durable database and object adapter on separately accounted volumes | Dedicated 10 Gbit/s link, shaped to 5 ms RTT; same path for both systems, loss 0% | Hosts, durable adapters and link capacity NOT ALLOCATED/NOT VERIFIED | UNAPPROVED |
| scaled | 11 Linux hosts: 3 authority/database hosts × 16 cores; 2 regional cache hosts × 16 cores; 4 node/client hosts × 16 cores; 2 load hosts × 16 cores | 64 GiB on every host | Authority 2 TiB NVMe/host; regional 1 TiB/host; node 512 GiB/host; load 512 GiB/host; separate 8 TiB durable object capacity; 1 GiB/s and 50000 random 4 KiB IOPS per service disk | 10 Gbit/s intra-region; client/node RTT 1 ms, node/regional 5 ms, regional/authority 40 ms; two logical regions, 2 Gbit/s inter-region cap, loss 0%; partition fault lane separate | Fleet, topology, storage/backend, credentials and capacity NOT ALLOCATED/NOT VERIFIED | UNAPPROVED |

Durability is part of the selected backend's contract. A local durable adapter, emulator and real cloud adapter get separate result namespaces; an emulator cannot certify cloud IAM, failover or scaling. A future cloud campaign must name the actual provider, region, service classes, quotas, storage consistency, replication and per-unit prices in the ratification manifest; absent choices block execution. This plan selects no billable service. Real FUSE lanes need a verified Linux mount and permitted isolation mechanism; Docker availability alone is insufficient.

Cache upper bounds apply per daemon and physical dataset headroom excludes compression assumptions. Low-reuse uses a rotating subset larger than the sum of all active node caches. Count authority/regional caches independently and report their bounded capacities too; propose 0.25 GiB regional cache for local, 1 GiB for medium and 32 GiB per regional host for scaled, all UNAPPROVED. No full native repository mirror is required at serving tiers. If dataset, compaction, duplicate A/B volumes, snapshots and retained evidence do not fit together, fail preflight, retain the requested scope, and obtain an owner decision.

## Matched Git baseline and execution protocol

Git is an external comparator, never a hidden implementation dependency of native queries. First run native-only gates with Git absent from service PATH and process auditing enabled. On the baseline host record the exact `git --version`, binary digest, build options, platform, complete command lines and effective `git config --show-origin --list` after credential redaction. The observed worker version is Git 2.54.0; the future campaign must pin its chosen version rather than assume that observation transfers to other hosts.

Use independently prepared synthetic repositories with identical logical bytes, paths, modes, ordered parents and source revision mappings. Feed identical semantic traces and verify outputs against the same oracle. For interactive developer and agent sparse reads, use `git clone --filter=blob:none --no-checkout`, then `git sparse-checkout init --cone` and `git sparse-checkout set` for the same directory selection, and checkout the mapped revision. Use non-cone sparse patterns when exact file selections require them and record those patterns. Full-content CI uses an ordinary full clone; shallow `--depth` is permitted only in a separately named lane whose native history scope is equally truncated and has no deeper query. Preserve byte-edge path API cases independently from unsupported filesystem materialization.

Baseline query mappings include `git show <revision>:<path>`, `ls-tree -z`, `diff --no-ext-diff --no-textconv`, `merge-base --all`, `merge-base --is-ancestor`, `log --first-parent` and `blame --first-parent`; fix rename detection, diff algorithm, line ending and blame options in the manifest. Compare only semantics supported by the chosen native history policy. Use `hash-object`/`mktree`/`commit-tree` and `update-ref` for detached commit/ref lanes, recording the adapter's generation/ABA semantics separately where Git lacks an equivalent. Import compares to reading/validating the same Git source stream with mappings preserved; review/CI service calls without a Git equivalent are native-only, not invented Git wins.

Enable appropriate maintained commit-graph, changed-path Bloom filters, multi-pack-index and bounded maintenance for the selected Git version. Record exact settings and preparation commands, index/repack duration, CPU, disk and amortized cost; do not exclude baseline preparation while including native preparation or the reverse. Honor promisor/remotes, lazy-fetch server CPU and network byte accounting. Match source content, selected paths, history horizon, authorization visibility, cache budget/state, filesystem, hardware, concurrency and network shaping. If Git cannot supply an equivalent permission projection, restrict both systems to an explicitly identical fully readable fixture view and leave projection performance native-only.

Alternate native/Git order by repetition (AB/BA/AB), restoring independent snapshots of authority/server state and cache conditions. Preflight hash manifests and permissions, record resource baselines, prime/reset as the case requires, execute the scheduled trace, drain within the run cap, and verify every result. SLO calibration, mixed trace, import, materialized/sparse/virtual checkout and fault lanes are distinct result sets. Record checkout bytes versus bytes actually read, graph latency versus depth, detached edit cost versus directory width at fixed edit size, import throughput/RSS, concurrent landing retries/fairness, and review/CI invalidation interactions. No baseline executes imported hooks, external diff/text conversion, untrusted build scripts or arbitrary repo configuration; use isolated HOME/config and disable hooks for both fixture preparation and commands.

## Correctness and safety gates before performance counts

| Gate | Required evidence on the same candidate/backend | Failure disposition |
|---|---|---|
| G-data | Independent byte/frame/hash vectors; replayed first-parent trees; bounded graph oracle returning all best bases; mode, byte-path, signature/mapping and unsupported-input fidelity; native processes make no Git calls | Any wrong answer/corruption invalidates the lane; unsupported scope remains blocked |
| G-durable | Real durable-backend restarts at publication stages; acknowledged blobs/parents survive; timeout-after-commit idempotency; changed payload with same key rejected; detached commits independent of refs; CAS generation/ABA and concurrent writers | Lost acknowledgement, duplicated effect, false success or global serialization blocks claims |
| G-auth | Cross-repo known digest, warm cache, range/resume, restricted directory/metadata/history/search/snapshot and stale projection attacks at every serving tier; current-grant checks before cache/upstream access; same-UID job isolation | Unauthorized disclosure or pre-auth cache probe blocks all performance claims on that revision |
| G-freshness | Current policy/version and bounded clock evidence, event-feed delay/partition, stream/handle revocation; test the contract's proposed 30-second bound only after owner ratification | Unratified bound, unbounded clock error, stale bytes or fail-open behavior blocks qualification |
| G-failure | No cache-topology bypass; bounded fan-out/retries, queues, CPU/RSS/bytes, expansion and history work; corrupt cache, miss storms, authority/region loss, partial snapshots and restore | Unknown success, unchecked resource growth or omitted fault evidence blocks claims |
| G-workspace | Real Linux FUSE/checkout isolation, interrupted checkout, dirty-file and symlink races, lost watcher events; stale review/CI approval rejected on changed source/policy and combined revisions | Missing real OS capability remains a named blocker; mocks do not satisfy it |
| G-evidence | Complete raw outcomes, seed/trace/source/contract/environment identity; independent review of exact submitted SHA, director integration and criterion verification at integration SHA | Missing review, changed SHA, skips or fabricated/trimmed results prevent acceptance |

Zero safety violations is the required gate, not a statistical tolerance. A document check does not execute any of these gates. This task's worker does not submit, approve, review, integrate, accept or close its own assignment. Performance qualification depends on separately implemented and reviewed capabilities; missing gates cannot be relabeled optional to make a release green.

## Metrics, artifacts and interpretation

For every operation × payload × caller × cache case × profile × backend × repetition, retain scheduled/offered/completed counts, expected denials/conflicts, unexpected failures by typed code, retries, timeouts, cancellations and dropped arrivals. Emit p50/p95/p99 end-to-end and service latency plus queue wait, successful operations/s, useful bytes/s and wall time. Latency histograms include failures in separate labeled distributions; display timeout lower bounds and failure rate alongside successful latency. Do not replace a timed-out request with its successful retry. Preserve per-repetition histograms and variability; never average percentiles.

Report total and per-component CPU-seconds, peak and steady RSS, local storage (dataset, indexes, caches, snapshots, logs and peak temporary bytes), transferred logical/compressed/wire bytes in each direction, upstream request counts by tier/outcome, index lag from durable acknowledgement to query-visible watermark, and instantaneous/peak/p95 queue depth. Steady RSS is the median of samples during the middle half of measured time; sample RSS/queues every second and use OS high-water accounting for peaks. Distinguish native filesystem cache, OS page cache and Git object cache.

At each tier define **object hit rate** = authorized whole-object lookups completely satisfied there / all authorized whole-object lookups reaching that tier. Count retries separately and also publish a deduplicated logical-demand view. Define **byte hit rate** = verified requested payload bytes served by that tier without an upstream fetch / total verified requested payload bytes demanded at that tier, including misses. For range requests use separate range/byte denominators; do not call a partial-object hit a whole-object hit. Denials, failed auth and zero-length payloads have separate counts and never inflate byte ratios; a zero denominator is undefined. Report hit and denominator integers, workload/cache capacities and per-caller results; a global ratio alone is insufficient.

Required artifacts are the immutable plan/ratification manifest; generator/oracle/binary SHAs; dataset and unsupported-input manifests; all seeds and trace hashes; commands/stdout/stderr/exit codes and UTC timestamps; environment/backend/versions/options; source and integration SHA plus contract and policy/index versions; raw event JSONL, histograms, resource time series, correctness/fault results, cache numerator/denominator tables, network counters and price/cost ledger. Hash artifacts, redact secrets without losing fixture identity, and record redactions. Keep partial/failed runs with their stop reason. Summaries link criterion-level evidence and distinguish implemented, verified-local, verified-cloud and verified-scale.

Collect per-cell samples across all three seeds. A p99 is descriptive only with at least 10,000 completed observations in that cell; otherwise mark tail evidence insufficient and retain the estimate/count. No repetition extends past its budget to manufacture samples. Report the seed-to-seed range and an independently specified confidence method when the analysis tooling exists. No private source-article speedup, cache ratio or fleet volume is an acceptance fact; any future comparison states both raw distributions and its precisely matched scope.

## USD ceilings, campaign arithmetic and hard stops (UNAPPROVED)

Current authorized incremental cloud spend is **USD 0**. The ceilings below are proposals for a future explicitly approved execution plan; they authorize no paid run, reservation, API call, storage allocation or credential use. Local runs use already owned resources with no incremental purchase; report estimated internal cost separately. Prices are planning upper bounds, not provider quotes. Exceeding a bound requires a new owner decision before execution.

A **run** is one complete system/profile/cache/composition lane including setup, warmup, three repetitions, drain and artifact preservation. Local smoke combines its full matrix for one system into one run; local correctness uses one cell per run. Medium and scaled caps are per lane. Dedicated SLO calibration and fault lanes use the same per-run cap and consume campaign slots. A **qualification campaign** includes both native and Git: 6 cases × 4 compositions × 2 systems = 48 runs, plus at most 12 SLO-calibration/fault/rerun lanes = 60 total. Runs are sequential for matched A/B; failed/stopped runs consume a slot and budget. Prerequisite correctness/safety evidence must already exist on the same revision/backend, or fit inside the capped fault lanes; otherwise the campaign remains blocked.

| Profile/budget ID | USD run ceiling | Wall hard stop minutes | Compute bound USD/h | Storage bound USD/h | Network/request bound USD/run | Proposed campaign run count | USD campaign ceiling | Campaign elapsed hard stop hours | Status |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| local-smoke | 0 | 45 | 0 | 0 | 0 | 2 | 0 | 2 | UNAPPROVED |
| local-correctness | 0 | 45 | 0 | 0 | 0 | 60 | 0 | 48 | UNAPPROVED |
| medium | 10 | 45 | 4 | 1 | 2 | 60 | 600 | 48 | UNAPPROVED |
| scaled | 150 | 60 | 80 | 12 | 20 | 60 | 9000 | 72 | UNAPPROVED |

The scaled ceiling is concrete: at most (USD 80 compute + USD 12 storage) × 1 hour + USD 20 transfer/requests = USD 112 estimated worst planned cost, leaving USD 38 for metering delay and teardown, within USD 150/run. Medium is (USD 4 + USD 1) × 0.75 hour + USD 2 = USD 5.75, leaving USD 4.25. Campaign ceilings equal run-count × run-ceiling, inclusive of setup, paired baseline, snapshots, requests, egress, taxes, retained artifacts and teardown; there is no uncapped shared-preparation bucket. Any provider price/tax/retention model that cannot fit must block ratification rather than silently use these estimates as quotes.

Check the full-scope projected bill before allocation, every 60 seconds while running and after termination. At 80% of either USD cap stop new arrivals/provisioning and begin drain/teardown; enforce resource termination by the wall hard stop measured from the first chargeable allocation (local from suite start). Independent watchdog and provider quotas must bound delayed billing, leftover disks/IPs, artifacts, and automatic retries; reserve remaining headroom for cleanup and retain stop evidence. If reliable stop/teardown permissions or cost telemetry are absent, do not start. Never stop safety auditing to preserve throughput. Default retained-artifact lifetime is at most 24 hours within the charged campaign budget, with an explicitly approved archive/export before deletion; retention beyond the cap requires prior funding or blocks execution. No resources are allocated by this document.

The standard medium/scaled cell needs 4 × 60 seconds = 4 measured/warmup minutes, leaving setup/drain budget inside its cap. A paired full matrix consumes at most 48 lane-hours scaled plus up to 12 calibration/fault lane-hours = 60 hours, with at most 12 hours for budgeted inter-run orchestration inside the 72-hour campaign stop. Medium and local correctness maxima are 60 × 45 minutes = 45 hours within 48 hours. A local correctness cell requires 4 × 30 seconds = 2 minutes before setup/drain; run each cell separately and retain suite incompleteness until all required cells complete. Local smoke's full 24-cell matrix × 4 × 5 seconds = 8 minutes per system fits its 45-minute run cap; its 2-run campaign includes both systems. Correctness has no performance SLO floor claim beyond its explicitly executed S1 lane. Slow setup/generation, insufficient samples or an expired cap leaves a partial/blocked campaign, not permission to raise limits automatically.

## Owner ratification and visible blocker ledger

All items below remain open. They are execution/qualification blockers, not failures of this documentation proposal. The director owns task state; this document does not change the board or downgrade R47.

| Blocker | Owner/action required | Present state | Closure evidence |
|---|---|---|---|
| B-targets | Product owner + performance lead ratify each profile, mix, seed schedule, S1–S12 payload/SLO and resource/error hypothesis, cache case and sampling rule | BLOCKED — all proposed numbers UNAPPROVED | Signed versioned ratification naming this plan SHA and explicit deviations |
| B-capacity | Infrastructure owner allocate measured local/medium/scaled hardware, storage headroom and network topology; verify load-generator headroom and dedicated capacity | BLOCKED — medium/scaled unavailable; nominal local host is not a scale measurement | Inventory, preflight throughput/IOPS/link evidence, quota/placement record and backend versions |
| B-budget | Budget owner approve provider/region/SKU prices, currency/tax accounting, per-run/campaign caps, cost polling, watchdog, teardown and artifact retention | BLOCKED — authorized cloud spend USD 0 | Explicit scoped execution authorization and verified independent stop path; this proposal alone is insufficient |
| B-credentials | Infrastructure/security owner supply least-privilege isolated test-project identities with teardown authority through approved secret handling | BLOCKED — no campaign credentials established | Redacted identity/scope and positive/negative authorization preflight; never put credentials in artifacts |
| B-contracts | Contract owners finish pending wire/codec/projection/backend decisions without silently changing packet inputs | BLOCKED for execution where interfaces remain proposals | Accepted compatible contracts plus regenerated trace/oracle manifest at their exact hashes |
| B-runner | Assigned implementation owners deliver generator, independent oracle, metrics, cost guard and safe Git adapter with reviewed reproducibility vectors | BLOCKED — FND-11 creates no benchmark code | Reviewed source SHAs and identical generated manifests on repeat generation |
| B-safety | Security/storage/OS owners prove G-data through G-workspace, ratify the revocation/clock bound and supply real durable/FUSE/cloud evidence where required | BLOCKED — runtime bootstrap/document checks are insufficient | Per-gate actual-backend results, no required skips and qualified specialist review |
| B-acceptance | Director arrange independent exact-SHA review, integrate reviewed SHA and verify C1/C2 there; release owner retain unresolved R47 gates | PENDING — worker cannot self-accept | Independent review artifact, integration SHA and criterion-linked verification; cloud/scale statuses separate |

Ratification checklist: explicitly sign every blocker row's closure artifact; freeze exact dataset manifests and unsupported cases; choose the actual backend/hardware/region and Git configuration; reconcile sums, run count and full cost envelope; approve statistical sufficiency and failure reporting; demonstrate watchdog/teardown and credentials in an isolated test project; approve security/fidelity gates and review assignments; then issue an execution packet naming the plan SHA, source/contract SHAs, allowed resources, dates and budget owner. Missing approval, credentials or measured scale capacity keeps qualification **BLOCKED**. Owner approval of a number does not establish that the system meets it. Failed, skipped or unexecuted requirements remain in the qualification ledger.
