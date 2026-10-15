# Shared grant contract: grants-v1

This is the FND-GRANT-CONTRACT candidate, for independent review. It proposes a
shared interface freeze, not an authorization implementation. The accepted canonical
and security contracts govern; their older proposal labels do not undo their
recorded acceptance. The owner-approved maximum 30-second revocation bound is a
design target. These protocol/model checks do not prove runtime enforcement.

`api/proto/grants.proto` is the single message definition in
`canopy.common.v1`, Go package
`canopy.local/canopy/api/gen/common/v1;commonv1`. It owns no service. The rejected
FND-04/FND-05 attempt-2 schemas are context, not accepted dependencies or aliases
for this contract. Future owners import these types through the existing RPCs
below; this attempt does not edit those schemas. Never copy divergent grants.

## Authority and exact scope

Every request authenticates a principal and credential/session through verified
transport credentials (and protected local peer/job credentials at a daemon).
Repository IDs, request IDs, paths, TIDs, audience hints and body text establish
no identity or rights. Serving workloads never substitute their own rights for
the end principal. Authenticate before any protected lookup.

An ObjectGrant has purpose READ, exactly one canonical `(kind,TID)` OR exactly
one separately identified projection. No set, wildcard, descendant inheritance,
implicit history access or read-to-write conversion is allowed. Each batch item
has a separately validated grant or a denial, even if bytes are physically
shared. Duplicate requested scopes are invalid. A batch binding is not a grant.

A blob requires an authority-validated exact source/path reachability decision
under active membership, repository read and all ancestor traversal/file-read
rights. A raw changeset requires full-object-read: every represented directory
must be traversable/listable, every path and referenced object readable, and
every disclosed metadata field, parent and history identity authorized. Explicit
deny wins. One visible path or generic repository read is insufficient. When
this fails, deny raw access, or use an independently authorized projection via
the existing query/changeset API. Never silently replace a requested raw TID with
projection bytes. Projection IDs bind source, principal/session view, immutable
policy, exact selection, algorithm and projected content in protected state;
they expose no hidden source TID, paths, counts or raw roots. A projection grant
cannot fetch its raw source. Canonical v1 has only blob and changeset kinds.

## Wire identity and admission

All byte comparisons are exact. Each serialized grant is at most8192 bytes. Token is 1..4096 bytes; scope binding, view,
principal/session binding, read stream ID, batch binding, projection ID and
upload ID are exactly 32 bytes; repository exactly 16; audience 1..256;
request correlation exactly 16; idempotency key 16..128. The32-byte authority handles are
unguessable references, not self-authenticating permissions. A token may index
authenticated protected state; its permitted short representation is never
bearer authority. Resolve only after authenticating and checking the owning
principal/session and all mirrors.
Never parse a token to obtain a required client field.

ObjectGrant and UploadGrant preserve the first eight mirror tags: token=1,
scope=2, audience=3, policy=4, view=5, expiry=6, repository=7, principal/session=8.
Version=9 must be present GRANTS_V1 (1); purpose=10 must be present READ (1) or
UPLOAD (2), respectively. Zero/unknown version, purpose, kind or failure enum
is invalid. An upload token remains invalid in ObjectGrant even if an attacker
rewrites the public purpose; validate protected purpose and issuer domain too.
No token cryptographic construction is specified or presumed.

All `optional` scalars require presence unless an explicit exception is stated.
Policy is unsigned 64-bit, including 0; absent is different from present 0.
Expiry is signed integer **UTC Unix milliseconds**, in 1..253402300799999;
now equal to expiry is expired. Use no floats, nanos conversion, truncation or
local timezone interpretation. Grant issue/check times are protected records,
not client authority. All eight mirrors and version/purpose must match those
records. Empty bytes cannot stand for a required handle. Optional
`expected_policy_version` on initial issuance/initial BeginUpload is the sole
policy-presence exception: absent requests a current-policy decision; supplied
0 means require current policy 0. Read renewal requires `renew.expected_policy_version`; the top-level initial expectation must then be absent. BeginUpload may omit its expectation even on an identical-key retry: authority still compares the retained policy/view with current policy before issuing anything.
`existing_upload_id` is absent on first Begin and exactly32 when supplied.
`durable_object` is absent until finished; source/scope/extent/result oneofs must
have exactly one arm; an absent or UNSPECIFIED failure code is invalid. `full_payload` and `root` must be true when selected.

Validate the original wire before a protobuf library loses evidence: reject
unknown fields, unknown enum values, duplicate singular tags (even identical),
repeated occurrence/conflicting arms of a oneof, wrong wire types, nonminimal or
overflowing varints, truncation, illegal field zero and trailing malformed bytes.
Repeated message fields concatenate in wire order and obey their count bound;
zero-length required submessages fail semantic validation. All integers must fit
the declared type before conversion. Inspect lengths/counts before allocation.
Reject unknown versions instead of guessing compatibility. Reserve retired tags;
changes to this frozen semantic contract require review/versioning.

Structural failures are INVALID_INPUT/transport INVALID_ARGUMENT; authentication
failure is UNAUTHENTICATED. Malformed/unknown grant handles and hidden/missing or
unauthorized resources have identical NOT_AVAILABLE/NOT_FOUND public shape,
size class and pre-cache behavior. Do not include free-form hidden detail.
UNAVAILABLE means authority/freshness uncertainty, never stale permission.
Only an authenticated owner gets RESTART_REQUIRED for its own invalidated
session; unknown/other-owner handles get NOT_AVAILABLE. Protocol diagnostics may
identify a public field number, never a protected record or hidden identity.

## Public producers and consumers

The following is the required integration mapping for future control/object
attempts, not a claim that their rejected schemas already implement it. Existing
RPC names and responsibilities are retained. All common inputs/outputs are
actual named messages; wrappers may carry them without discarding presence.
Existing outer request/response envelopes retain correlation, trace, deadline,
per-call response/work limits and transport errors. The caller supplies bounded
per-call deadlines (1..30000ms), response/work limits and retry hints; these are
limits only. The responding service generates an opaque16-byte trace ID and
echoes the16-byte request ID. These fields never mint authority. Capabilities
retains its existing `envelope_versions=[1]`, `canonical_versions=[1]`,
`codecs` (RAW mandatory, GZIP only if implemented; 1..2 distinct values), ordered
bounded `limits` (each distinct existing nonzero ProtocolLimit value once), and
`max_upload_frame_bytes=1099511627798`. `Capabilities.discovery: DiscoveryCapabilities` supplements
these fields with the audience and limit producers below; it does not remove
or replace the existing transport/integrity discovery fields.

| Existing RPC | Input mapping | Named output producer and lifecycle |
|---|---|---|
| ObjectService.Capabilities | `CapabilitiesRequest.context` becomes `DiscoveryContext`; no grant, view, read stream or batch required | `CapabilitiesResponse.value.discovery` is `DiscoveryCapabilities`: `api_version`, `serving_audience`, `upload_audience`, all fixed advertised limits. Values are endpoint configuration, not resource existence or authorization. |
| IdentityPolicyService.IssueObjectGrants | request carries `IssueObjectGrantsInput`; first call selects `initial`, later calls `renew` | response carries `IssueObjectGrantsOutput.batch`: `context.stream_session_id`, `batch_binding`, `effective_view_id`, `policy_version`, `principal_session_binding`, `audience`; `outcomes[i].index/value.scope/grant/logical_payload_bytes/authorized_intervals`; `stream_expires_unix_millis`, `logical_byte_budget`, `consumed_logical_bytes`. All issued atomically after validation. |
| ObjectService.GetObjects | `context` is issued `ReadContext` with fresh caller request ID; each ordered wanted item carries its matching `outcomes[i].value.grant`; TID/kind matches `scope.object`; the stored selection MUST be `full_payload=true` with complete [0,payload) coverage, never range-only | Existing start/chunk/terminal responses echo the current item grant; successful terminal produces its existing completed-object resume token. That token is completion evidence only, not a grant, stream or renewed budget. |
| ObjectService.GetRangePlan | issued `ReadContext`, exact matching blob grant, TID and requested interval | Existing `value.plan` is integrity metadata and `value.grant` echoes the validated current grant. Neither creates read authority or changes selection. |
| ObjectService.GetObjectRange | same `ReadContext`, blob grant, interval and verified plan | Existing value echoes the grant and authorized bytes only. Plan geometry cannot widen intervals. |
| ChangesetService.GetChangeset (projection mode) | `GetChangesetRequest.projection_read: ProjectionReadInput`, copied from issued context, projection ID and its grant; this mode omits a raw changeset-ID selector | `GetChangesetResponse.projected` emits only that authorized ProjectedChangeset, matching the protected projection type/source/selection. The existing source-ID mode authorizes directly under current policy and can initially produce a projection identity. |
| QueryService.GetRootView (projection mode) | `GetRootViewRequest.projection_read: ProjectionReadInput`; source-revision selectors omitted in this mode | `GetRootViewResponse.authorized_manifest` emits only the corresponding authorized manifest reference under current policy. No raw tree route or hidden source is inferred. The existing source-selection mode can initially produce this identity. |
| UploadService.BeginUpload | request carries `BeginUploadInput`: discovery context, immutable intent, key, authority audience and optional policy expectation/known upload ID | response carries `BeginUploadOutput.session`: `upload_id`, distinct `grant`, `accepted_offset`, absolute `session_expires_unix_millis`, `max_frame_bytes`, `max_chunk_bytes`, `finished`, optional `durable_object`. Initial call and renewal share this producer. |
| UploadService.UploadChunks | request carries `UploadChunksInput`; `context.upload_id/grant` copied from Begin; offset starts at Begin's `accepted_offset` | response `UploadChunksOutput.progress.accepted_offset` produces the next durable offset. Lost responses use same chunk/offset, never invented progress. |
| UploadService.FinishUpload | request carries `FinishUploadInput`, same UploadContext and declared exact object/digest | response `FinishUploadOutput.durable.object/canonical_frame_bytes`; idempotent durable storage result only, no publication/ref move. |

Client-originated fields have explicit origins too: DiscoveryContext version is
constant 1, repository is the requested repository and request ID is fresh
correlation; initial key is caller-generated idempotency, desired audience comes
from Capabilities/configured authenticated endpoint, and selection/intent/TID/
path/range/budget are untrusted caller intent. Known revision IDs come from
existing authorized ref/query results or caller input; guesses still require
proof. A projection anchor/target can come from existing
`QueryService.GetRootViewResponse.authorized_manifest.projection_id` or
`ChangesetService.GetChangesetResponse.projected.projection_id`; identity alone
grants nothing. There is no mandatory out-of-band proof token. Authority resolves
source/path reachability itself. It may reuse protected validated proof state.

The only bootstrap is authenticated discovery followed by IssueObjectGrants or
BeginUpload. No client fabricates stream/session/batch/view/scope handles, parses
a token, calls an unnamed endpoint or reuses a request ID as authority. READ
projection grants are consumed by the two explicit projection-read modes above;
ObjectService raw TID methods reject them. Consumer owners add the named
`projection_read` field using the shared message in their future attempts; no
present rejected candidate is asserted to have this field. The protected record
classifies the projection as ProjectedChangeset or AuthorizedManifestReference;
the wrong method/type fails without disclosing its source. Its payload size is
the uncompressed encoded existing projected result (excluding RPC envelope),
which the authority determines, never a caller estimate. These control modes
charge the same read ledger and freshness rules. They cannot return projected
bytes under canonical envelopes. Consumer owners retain their other protocol
criteria, including their explicit projected representation encodings.

## Read issuance, renewal, expiry and accounting

InitialRead contains 1..128 ordered ReadSelections and an explicit total requested
logical budget (0..2^40). Authority chooses a cap no greater than that explicit
request and its authorized quota; client hints never enlarge authority. A zero
cap permits no positive payload delivery. Validate the entire structural request before resource
lookups. All source anchors in a batch must resolve to the same source revision and
effective view under the current policy; a projection anchor resolves this
privately without exposing its hidden source. Use separate initial batches for
different source views. Evaluate each item under that one policy/view; return exactly one
indexed grant-or-denial per input, preserving order, with no hidden counts. A
denied item contains no scope/size/grant echo. A request may return all denials;
it still consumes one finite retained session slot. Exhausted quota may reject
the entire request without a session.

For a blob, `source` and exact non-root `path` must resolve to its TID.
Read selections reject the upload-only empty-repository anchor. For raw
changeset, `source.revision_tid` equals its TID, `path.root=true` and full extent
are required; authority performs full-object-read. Projection source and exact
selection must match its protected projection record. Full extent resolves to
[0, verified payload size); ranges are explicit offset/length, sorted, disjoint,
nonadjacent (merge adjacent intervals before initial submission), 1..64. Each
end is checked without overflow and <=payload<=2^40. Length zero is permitted
only as the single [0,0) interval for an empty payload. A grant protects the one
scope and these exact intervals, with one shared aggregate budget across items.

IssueObjectGrants mints a random public stream ID and random batch binding.
Protected state records authenticated owner, repository, exact ordered selection
(target kind/identity, source, exact path/root and full/ranges mode plus values),
resolved size/intervals, per-item authorization outcomes/proofs, policy/view,
absolute session expiry, total budget, consumed/reserved counters and idempotency
key. Bindings must not encode raw paths, source roots, hidden counts or hashes
that allow dictionary inference. They are stable only for that session.
Initial same-key/same immutable request retries return the same session/ledger
with current authorization only while the original policy/view is unchanged;
any such change returns RESTART_REQUIRED even on an initial same-key retry,
without refreshing the old binding. A changed tuple is CONFLICT. The key includes the
initial audience/budget/selection; renewal uses the renewal arm instead.

RenewRead supplies the original stream ID, batch binding, exact original ordered
selection, expected policy and view; no old grant token is required. Authority
authenticates anew, resolves this owner's state, checks current policy and all
proofs, then returns the same stream/batch, same outcomes, sizes, intervals,
budget and expiry, with new grants and current consumed snapshot. Reordering,
changing identity/source/path/extent/range, adding/removing an item or replacing
a denial requires a new explicit initial authorization. No implicit narrowing or
widening on this renewal path. A new initial request needs explicit new-budget
admission under per-principal/session quotas; it cannot reuse or overwrite an
existing idempotency key to reset consumption.

A routing-only renewal can request another exact configured audience through
IssueObjectGrants. Its new tokens bind that recipient while preserving the same
protected ledger and selection. Existing tokens remain confined to their old
audience/lifetime; all audiences share atomic consumption/reservation. Fetch
routing stays node -> regional -> authority. Reissue is control traffic, never
permission to bypass a failed regional tier or overload authority. No wildcard,
string-prefix, service-class approximation or cross-audience token forwarding.

A policy/version/view change invalidates the whole old stream, grants, projections
and completion tokens. Return RESTART_REQUIRED to its authenticated owner, no
new grants or data. Client must make a fresh initial current-policy decision;
old consumed state is not reset or credited. Session expires at its original
creation+at most 1 hour; renewal cannot extend it or resurrect collected state.
Old keys are retained through that expiry; expired IDs never implicitly restart.
Idempotency is guaranteed only within this retention window. After state expiry
and collection, the client must choose a new key for an explicit initial request;
that request undergoes fresh full authorization and quota admission and creates
a distinct budget decision, never continuation or credit of an expired stream.
The existing read RPCs have unary requests, not a hidden bidirectional refresh
channel. Renewal returns credentials for the next call. An in-flight call must
stop at its original grant/freshness expiry; obtain IssueObjectGrants renewal
and reopen the same read with the same stream/selection and current grants.
Per item, `SKIP_VERIFIED` requires a still-valid completion token plus retained,
fully verified local bytes. With a valid token, explicit `REDELIVER` transfers
from zero and charges again. Without a valid token, omit the token and use the
existing `RESUME_UNSPECIFIED` start-from-zero action; partial objects also restart
from zero and charge all retransmitted bytes. Sending an expired, mismatched or
invalid token fails that item with no implicit skip, restart or fallback.
No client can inject a renewed grant into an already admitted unary request.
Existing projections must be reacquired under current policy where appropriate.

GetObjects consumes an exact ordered whole-object batch: every selection must
be canonical with full_payload=true, and the wanted list must match the stored
ordered list. Mixed projection/range batches use the individual projection/range
consumers instead; they cannot be relabeled as a whole-object batch.
Read methods match every supplied context field, item identity/order and grant
to protected state, then recheck before each delivery including cache, snapshot,
range, replay, skip and local daemon use. Range calls select only a matching
item/authorized interval; they cannot create a new batch. Reserve logical bytes
atomically before lookup; debit every exposed payload byte, including redelivery
of already delivered bytes and bytes sent before disconnect. Charge canonical
payload (header excluded), not compressed size; projections charge their emitted
logical bytes. A skip with verified completion emits no payload, but still
requires current authorization. Concurrent attempts cannot spend the same
remaining bytes. One active delivery call per stream; other calls conflict.
Unused reservation may be released, consumed bytes never refunded. Counter
snapshots are informational: clients cannot set them, and changing audiences,
request IDs, resume tokens, deadlines or grants cannot reset them. Expiration
or denial stops further bytes; already delivered plaintext cannot be recalled.

## Upload bootstrap and renewal

UploadGrant authorizes staging and durable object storage for exactly one
immutable UploadIntent, key and upload session, never publication/ref mutation.
It cannot be accepted as READ; ObjectGrant cannot be accepted here. BeginUpload
is authority-only, never registered at caches. No read stream or batch is used.

Begin authenticates and checks active membership, repository write capability,
current policy, ancestor traversal and authority-resolved destination proof,
then reserves finite session/staging/work quotas before returning a grant/ID.
A first upload into an empty repository uses explicit
`destination_base.empty_repository=true`; authority proves the repository has
no base under the relevant write permission. False or use as a read anchor is
invalid. This is a caller intent checked against state, not a fabricated revision
or a requirement to call another endpoint.
For blob, boundary is one exact destination path. For changeset, ROOT or a prefix
must cover all eventual operations, and authority must prove write permission
throughout that boundary (including descendant deny rules), plus the existing repository write capability for the declared author,
committer, message and parent metadata. This defines no new metadata-write or
history-write permission. Resolving the base/parents requires the existing
metadata-read/history-read capabilities for every identity disclosed to the
caller; object staging never grants those read rights. A broad boundary is caller intent, never permission.
If coverage cannot be proved within bounds, deny/exhaust; never grant broadly
and rely only on Finish. Finish additionally checks every actual operation,
referenced object and repository-write obligation for metadata/parent changes
against current policy and that boundary. Any returned metadata/history also
requires its existing metadata-read/history-read right; no upload grants reads. Restricted clients may choose a narrower covered boundary;
this does not change any canonical object maximum or grant missing rights.

Intent binds exact object kind/TID, source base/projection, byte-exact boundary,
envelope version=1, RAW codec, declared canonical/encoded frame lengths. Both
lengths equal payload+22: blob <=2^40+22, changeset <=67108864+22; min22 (empty
blob only). Preserve canonical parser constraints, path/parent/operation maxima
and full frame integrity. No gzip or envelope serialization enters this upload
byte stream. The authority validates header, kind, length, complete canonical
payload and expected digest before successful Finish, including for dedup hits.

Repeat Begin with identical intent/key authenticates current write authorization
anew and returns SAME session, durable offset, original absolute expiry and
idempotent finished outcome with a new <=30s UploadGrant. Supplying the known
upload ID is optional on lost-first-response retry; when supplied it must match.
An optional policy expectation, when supplied (including0), must equal current
and retained policy. With no expectation, authority still compares retained
policy/view to the current decision; mismatch returns RESTART_REQUIRED. Thus a
lost initial response can be recovered with the same key/intent and fresh
authentication alone, without any expired token, unknown policy or invented ID.

Changed intent/key binding or mismatched ID conflicts. An expired previous grant
is neither required nor used to authorize Begin, avoiding an expired-token
bootstrap loop. Policy/view changes require a new upload decision/session;
old staging is inaccessible and expires, without silently rebinding a session.
No automatic retry after session expiry; use explicit new key and admission.
After collection, there is no cross-expiry idempotency guarantee. A Begin with
no existing ID is an explicit fresh admission at that point, never continuation
or credit of the old upload; fresh policy, proof and quotas all apply. Known or
provided expired upload IDs cannot bootstrap a replacement session.
Completed sessions/results count toward the same 8 retained-session quota.
A routing-only reissue to another configured authority recipient uses the same
Begin exchange; it preserves the upload ID, original expiry, progress, consumed
ingress/work counters and finished result. The new grant has that one exact
audience; old-audience grants cannot be forwarded. Caches never accept uploads.

UploadChunks authenticates current UploadGrant/session, reserves work and handles
one 4MiB scheduled chunk (last may be smaller); offsets count RAW frame bytes.
Only append at durable accepted_offset. A byte-identical complete prior chunk
replay returns current durable offset without storing it twice; gap, overlap,
changed data/tuple or overflow conflicts. Each replay still consumes ingress/work
budget. Serialize per-upload metadata updates, not repository-wide commits.
Acknowledge only durable staging and progress. Lost/uncertain outcome requires
same-tuple retry. Finish requires full frame, current authorization, durable
verified object and durable result; same Finish returns same result. It does
not create/publish a changeset or move a ref. An unknown durability result is
UNAVAILABLE, never success. No data disclosure from other-owner upload handles.

## Freshness and finite resource rules

Reject time overflow or an unrepresentable UTC deadline rather than wrapping.
Every grant expires no later than authoritative issue time+30000ms and session
expiry. Every tier's authenticated policy-freshness lease expires no later than
its own authoritative check time+30000ms. Immediately honor known revocation.
At each serving boundary require both expiries and no newer known policy; leases
and grants cannot renew one another or compound their delays. A fresh grant
requires a current committed-policy decision; renewing a lease cannot validate
an old revoked grant. Charge maximum clock error before expiry: require
`local_now + clock_error < expiry` for both, with checked addition. Unknown clock
error, unavailable freshness or stale/revoked state fails closed. A clock-error
bound is a nonnegative integer of at most30000ms; if it consumes the remaining
validity there is no valid serving window. No party may assume a zero error
without measured bounds. Authority must
also account for its own bounded clock/check uncertainty in the 30000ms bound.
These records are protected, not public timestamps trusted from a client.
Runtime tests must later measure commit-to-last-byte across every tier, open
stream, cache and daemon; the finite model is not such evidence.

| Resource | Mandatory bound/admission rule |
|---|---|
| Wire messages | Common discovery/issuance/read metadata <=2MiB; Begin <=2MiB; chunk requests <=8MiB; all responses <=16MiB, uncompressed protobuf before 5-byte gRPC prefix; depth<=16. Compression disabled for these authorization messages. |
| Per-field proof work | No client opaque proof required; any retained resolved proof <=1MiB; source/path fields retain canonical 65535-byte/1024-component maximum. |
| Selection and state | 128 items, 64 intervals/item; each stream including all proofs/selection/counters/completion records <=2MiB, <=128 completion records. Oversized authorized work returns RESOURCE_EXHAUSTED. |
| Read session | <=8 retained sessions/principal+credential session, <=8 in-flight calls overall, one active delivery/stream, <=1h absolute lifetime, <=2^40 aggregate logical bytes across all replays/audiences. |
| Read transport | Existing object cap128MiB/call, <=8192 frames, <=16MiB/frame, 4MiB chunks and reserved terminals remain consumer obligations; frame cap67108886 preserves 64MiB changeset plus22 header. Blob ranges support2^40 payload. |
| Authorization evaluation | <=16,777,216 work units/request; unit per policy-rule comparison, graph edge, path component or canonical operation visited (charge each); <=65,536 policy rules, <=1,048,576 object/edge visits and <=4096 traversal depth; abort before exceeding any bound. Preserve 1,000,000 canonical operations and1024 parents as format limits. |
| Upload state | <=8 retained active/finished sessions per principal+credential session, <=2^40+22 aggregate staging reservation, <=2MiB metadata/session, <=1h original expiry. At most262145 distinct scheduled chunks; retain fixed geometry and a durable offset rather than an unbounded per-chunk map. |
| Upload ingress/work | <=4*(declared frame bytes) cumulative ingress including duplicate chunks, <=1,048,580 chunk attempts/session, <=8 in-flight overall, one mutating call/upload; exceeding budget stops, does not reset on Begin renewal. |
| Clock/scalars | All sizes/counters uint64, bounded by the tighter row before addition/multiplication/allocation; use checked subtraction for remaining budget. No saturation, wrapping or unchecked cast; enforce declared protobuf ranges. |

Compact upload records may store one 32-byte digest per distinct chunk, which
would exceed 2MiB at maximum blob size. Therefore do not retain all digests in
session metadata: replay comparison reads the bounded staged chunk by offset
or rehashes it with bounded4MiB memory/work. Only durable accepted offset, fixed
chunk geometry, bounded per-call progress and final result are retained. A
262145-chunk object is not reduced to fit an in-memory checksum table.

Aggregate session/rate/storage quotas are shared across audience reissue and
concurrent calls. Queue depth<=8 per authenticated credential session; fail
admission rather than accumulating unlimited pending requests. Resource failure
never bypasses cache ordering, performs unbounded proof work or returns raw
fallback. All retained state expires/collects at original expiry. Limits bound
admission, not silently revise canonical formats or eliminate blocked full-scope
requirements. Runtime quota enforcement remains unimplemented here.

## Evidence boundary

`tests/fixtures/grants_v1.json` supplies finite flow/state scenarios. Attempt
criterion evidence compiles the real protoc35.1 descriptor, exercises actual
text encoding and literal presence/wire vectors, checks original-wire rejection,
and models issuance, renewal, purpose, freshness and accounting. This proves
specified protocol/model properties only. No server, real credential verifier,
durable ledger, clock enforcement, cloud deployment or scale benchmark is
implemented or verified by this change. Independent exact-SHA review and later
integration verification remain required; this worker cannot accept the task.
