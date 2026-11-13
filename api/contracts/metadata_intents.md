# Internal metadata operation identity (`metadata-intent-v1`)

This original Canopy internal format binds the actual typed operation passed to
a metadata backend. It is not an external RPC, a signature, authentication,
authorization, proof of durable storage or proof of graph/path visibility.
An intent digest is never bearer permission. Principal, session, audience and
current policy are separately compared with protected authority state.

All transcripts begin with literal bytes
`CANOPY\x00INTERNAL-METADATA-INTENT\x00V1\x00`, an operation `u16be`, and the
repository's exact 16 bytes. No JSON, normalization, padding or extra fields enter
the digest. The digest is SHA-256 over the complete transcript.

| Operation | Remaining fields in order |
|---|---|
| 1: publication mutation | Mutation key as `u32be(length) || raw`; event with identical framing; full 35-byte kind02 ChangesetID; canonical SHA-256 (32 bytes); full canonical frame length `u64be` |
| 2: publication tuple lookup | Exact 35-byte kind02 ChangesetID |
| 3: publication mutation status | Mutation key as `u32be(length) || raw` |

Keys are 1..1024 raw bytes and events 1..128 raw bytes, matching the existing
metadata-v1 SQL ceilings. Canonical frames remain bounded by the unchanged
canonical-v1 format: payload <=64 MiB plus 22 header bytes. The service digest
preparation helper ignores asserted `Mutation.RequestDigest`; the backend's
`NewPublicationIntent` additionally requires it to equal the recomputed value.
The actual canonical content hash must match the actual typed ID, and the
canonical repository must match the requested scope. Hashing streams into a
bounded prefix/counter/hash, without retaining canonical bytes or cloning a
whole Changeset snapshot. Canonical-v1 puts the repository at frame bytes 22..37.
Every failure returns a zero result. Context cancellation is preserved.

Publication author, message, parents (including order/duplicates), operations
and optional presence affect the canonical hash. Event and key are independently
bound even for content reuse. Principal/session/policy changes intentionally do
not alter a retry's immutable mutation digest; retries require fresh authority.
Lookup identifies only the exact Publication tuple, never raw Changeset bytes.
Status is separately scoped to the authenticated principal's retained mutation.
The invalid zero OperationIntent cannot authorize or identify an operation.

## Independent literal

Use repository hex `01000000000000000000000000000000`, no parents, empty author
identity with time/offset 0, absent committer, message hex `ff00`, absent encoding
and no operations. The complete canonical frame is 68 bytes and has SHA-256
`a15c4cb01b7ec5f73279d11ea3240dd312942b7bac370d33c34d73bbbc867828`.
Its typed ID is prefix hex `000102` followed by that hash. With key bytes
`mutation\x00\xff` and event bytes `event/\xff`, the publication digest is
`4717c5024436ca7370b852f0bafde2ff1ed5b84ef73e7936c88356af135b5ec9`;
lookup is `1571cefa14d867103db270b0fb710ecbe32dc418e53dff203d7e87a939a298e6`;
status is `f1e76556fd7a72e60d4465eb50cea133d82bafb78fd52197ecb8dc01f6457b13`.

## Integration gate retained

`PostgresIntentAuthorization` is additive to the existing foundation interface.
Actual publication/lookup/status methods must recompute their own complete
typed request before protected lookup and require this provider; absent/typed-nil
providers must fail closed, never fall back to string-only authorization.
Recheck and Finalize must use the same checked database transaction and retain
policy/session guards through commit. Finalize checks expiry/cancellation just
before commit admission, not the physical WAL durability instant.

This change supplies neither that concrete provider nor actual Port methods.
Trusted descriptor preparation must still derive complete input/output paths,
metadata/history rights, object provenance, reachability and durable retention
from real providers; callers cannot supply their own rights or path maps.
Object delivery, current policy, unknown commit outcomes, service workflows,
cloud and scale remain separate required acceptance work.
