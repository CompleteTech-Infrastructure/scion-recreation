# Policy runtime contract: policy-runtime-v1

This contract describes the local Canopy policy runtime in
`internal/storage/policy`, including the repairs to the independent review
findings for PR296 / #278. It specifies no unpublished Anthropic behavior.
The signed byte formats remain [session-v1](sessions.md); the schema remains
`policy-local-v1`. This document changes neither format nor database catalog.

## Clock uncertainty and acknowledgement

Trusted deployment configuration supplies a clock and an explicitly known
nonnegative maximum absolute error `e <= 1 second`. Unknown error bounds,
missing/error/zero/out-of-range clock readings and canceled contexts fail closed.
The clock must remain trustworthy; the runtime does not measure its actual error.
For a signed session interval `[not_before, expiry)` and reading `t`, admission
requires both:

- `t - e >= not_before` (the earliest possible actual time is valid), and
- `t + e + 5 seconds < expiry` (the latest possible actual time leaves the
  transaction budget).

After a management transaction commits, the runtime checks the whole uncertainty
interval again, requiring `t - e >= not_before` and `t + e < expiry`, without
reserving another transaction budget. Checks bound values before time arithmetic.
Actual identity and session signatures, exact credential binding, and containment
of the session interval within the identity interval remain mandatory. Satisfying
these time checks alone confers no enrollment, membership or object permission.

A failed admission check aborts the transaction. A failed postcommit check cannot
undo a sent commit: management returns a zero receipt with `ErrOutcomeUnknown`
and an authentication error. A commit transport error also reports outcome
unknown. Callers may recover/retry the exact immutable request after fresh
successful authentication. Neither admission margins nor postcommit clock
readings prove that the physical WAL commit instant preceded signed expiry.

## Durable local PostgreSQL configuration

Every runtime operation uses its own private connection and verifies the pinned
installation, database identity, catalog, restricted role and bounded timeouts.
Caller DSNs and role/database defaults cannot opt out of synchronous commit:
the runtime sets `synchronous_commit=on` at connection startup and explicitly
sets it again after connecting, covering `options='-c synchronous_commit=off'`
as well as direct DSN parameters. An inability to set it fails before application
mutations. The trusted offline `Provision` path likewise overrides startup
settings, sets `SET LOCAL synchronous_commit=on` immediately after BEGIN, and
uses the same durability checks before any DDL and immediately before COMMIT.
Neither path alters server-wide configuration.

Within every transaction, before application work and again before COMMIT,
effective `fsync`, `full_page_writes`, and `synchronous_commit` must all equal
`on`. Missing/unreadable settings fail closed; unsafe values fail with
`ErrFailedPrecondition` before success or delivery. This applies to existing
handles, fresh opens, Provision, bootstrap, enrollment, revocations, policy updates,
authenticated reads and historical-result retries. Public authentication retains
its uniform `ErrUnauthenticated` denial and returns no authenticated context.
No catalog, signature, role or binding check is relaxed to satisfy durability.

With legitimate storage honoring PostgreSQL flush requests, these settings
require acknowledged writes to reach local durable WAL. `on` may also wait for
synchronous standbys when a deployment configures them; this runtime establishes
no replica, quorum, failover or cloud durability guarantee. The trusted deployment
must preserve safe server settings throughout service. Checks cannot fence a
hostile superuser changing configuration mid-operation, repair earlier unsafe
writes, attest hardware, or make faulty storage honor flush acknowledgements.
Uncertain commits never become assertions that rollback happened.

## Executable evidence and limits

`review_repair_test.go` covers nanosecond lower/upper interval boundaries,
zero/overflow/error clocks, actual signed bootstrap/enrollment/authentication,
and a real committed result followed by a failing postcommit lower-bound check.
Its opt-in owned PostgreSQL 18.6 fixture exercises hostile direct and `options`
DSNs and an asynchronous database default under all three restricted roles,
then immediately crashes its own persistent btrfs server separately after
acknowledged Provision, bootstrap, enrollment, CAS, session revocation and
credential revocation. Recovery must retain policy, authentication/revocation behavior and
the exact receipt/audit linkage. It also reloads disabled `fsync`
and `full_page_writes` only in that owned cluster and requires existing and new
handles to fail before changing application state. Provision must return a zero
binding before creating any schema under unsafe settings, and succeed after
legitimate durability settings are restored.

These are local process-crash and real PostgreSQL configuration checks, not
power-loss, physical WAL-expiry, production, cloud or scale qualification. Missing
fixture/toolchain skips are not capability evidence. Worker implementation and
local test results do not substitute for independent exact-SHA review,
integration, or criterion-level verification of the integration SHA.
