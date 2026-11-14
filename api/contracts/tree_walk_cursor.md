# Private stored TREE topology cursor v1

This original internal implementation serves #299, a prerequisite of #69/#177.
It preserves `tree_pages.md`; no external object, RPC, projection or grant format
changes. It checks only page topology. Blob bytes, durable graph retention,
publication, changed-path updates, job recovery and scale remain required work.

`NewTreeWalkCursor` accepts a typed root, trusted `TreeCandidateReader`, and a
finite cumulative work admission. `treepages.Staging` directly implements the
reader using its existing private, authorized `GetCandidate`. The reader is
constructor composition, never supplied by a request. Every read must honor
cancellation, authorize before probing/delivering and read no more than one
maximum frame plus an oversize sentinel. The cursor independently verifies the
full typed digest, frame syntax and exact directory/component anchoring.
Neither a known page ID nor successful topology traversal grants access.

`Advance` suspends with `TopologyDone=false` and nil error when its quantum is
exhausted. The next call resumes the exact in-process lazy DFS state, rather than
replaying an ever larger prefix. A quantum permits at most 4,096 page fetches,
4,096 terminals and 42,917,888 returned page bytes. A terminal is charged once
for every expanded occurrence, including directories and shared page contexts.
Fetches include ancestor re-reads: a shared page or hit never skips validation.
There are no blob validation reads in this cursor and consequently no blob
validation or complete-tree result.

Before each read, reserve one maximum frame (10,478 bytes) in both the quantum
and cumulative job budget, plus one possible terminal for a newly entered page.
Charge actual returned bytes and actual terminal presence after validation;
refund unused reservation. These conservative reservations can stop before a
small or nonterminal page which would fit if its content were already known.
An exhausted job fails with resource exhaustion and cannot reset its counters.
All budgets are positive and bounded; a quantum must fit a maximum frame.
A trusted reader returning excess bytes violates its contract: the cursor never
hashes/decodes the excess, charges the reserved maximum and permanently fails.
It cannot undo I/O already performed by a misbehaving provider.

The cursor retains a single path buffer of at most 65,535 bytes, at most 65,536
DFS frames and an active-ancestor identity set bounded by that stack. Each frame
contains offsets, identity and next edge, without an ancestor page buffer or
sibling queue. Ancestors are re-read and charged before selecting each next
edge. Directory edges append `/` and reset component position; radix edges
preserve the component. The same page under another prefix is checked again.
No complete frame map, leaf enumeration, canonical payload copy, mirror or
unbounded cache is retained. Deep traversal uses no recursive Go calls.

A provider error, invalid context/frame, cancellation, depth limit or cumulative
work exhaustion permanently fails this cursor. Every subsequent valid call
returns the same failure without reads or completion. Invalid configuration or
quantum arguments are rejected before work; they do not modify a live cursor.
Concurrent calls fail immediately with `ErrTreeWalkBusy`; there is no queue or
repository/global lock. Do not copy a cursor. Context is checked after reads,
on each loop, and even when revisiting an already completed cursor. Usage on
failure is accounting evidence, never a partial root or successful result.

This cursor is not serialized. Process loss discards it. Persisted source/job
bindings, checkpoints, counters, CAS fences, generation validity, closure pins,
blob receipts and restart-safe publication ownership remain separate mandatory
integration work. A caller must not treat a new cursor as a way to reset a
persisted job budget. `TopologyDone` is a private result of this attempt, not a
portable validation receipt. Storage generation loss and collection require
retention coordination before this may contribute to publication preflight.

Tests use the actual private staging store, including 5,588 expanded terminal
contexts over three unique staged frames. The corpus deliberately shares frames
to test logical occurrence accounting; it is not a million-entry capacity or
scale qualification. Other cases cover maximum byte paths, directories, empty
roots, one-fetch quanta, real missing/corrupt/denied files, invalid anchoring,
provider failure, cancellation, cumulative limits and concurrent admission.
Author execution is not independent review or accepted integration evidence.
