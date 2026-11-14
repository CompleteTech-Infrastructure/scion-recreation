# Internal session proof contract: session-v1

This is the final byte-order definition for the original Canopy internal
`session-v1` format implemented in `internal/authz/session.go`. It supersedes
previously proposed packet prose ordering the repository/session before the
credential hash. The implemented order is **credential hash, repository,
session** after the seven strings. This documentary amendment changes no source,
signature, or frozen vector. It specifies neither a public RPC/token envelope nor
unpublished Anthropic internals. Independent review of this document remains
required; documentation alone establishes no product capability.

## Signed transcript

`SessionClaims` and `SessionProof` are internal authz values. Concatenate the
following fields exactly, in table order, with no padding or implicit fields:

| Order | Field | Encoding |
|---|---|---|
| 1 | Purpose/version domain | Literal bytes `CANOPY\x00INTERNAL-SESSION\x00V1\x00` |
| 2 | Authority issuer | `u32be(byte_length) || raw_bytes` |
| 3 | Authority key ID | `u32be(byte_length) || raw_bytes` |
| 4 | Principal issuer | `u32be(byte_length) || raw_bytes` |
| 5 | Principal subject | `u32be(byte_length) || raw_bytes` |
| 6 | Principal class | `u32be(byte_length) || raw_bytes` |
| 7 | Audience | `u32be(byte_length) || raw_bytes` |
| 8 | Tenant | `u32be(byte_length) || raw_bytes` |
| 9 | Credential hash | Exactly 32 raw bytes |
| 10 | Repository | Exactly 16 raw bytes |
| 11 | Session | Exactly 32 raw bytes |
| 12 | Generation | Unsigned 64-bit big-endian integer; zero is valid |
| 13 | Not-before | Signed 64-bit UTC Unix seconds, big-endian bits |
| 14 | Expiry | Signed 64-bit UTC Unix seconds, big-endian bits |

Here `\x00` denotes one NUL byte. Strings are opaque bytes, including embedded
NUL and non-UTF-8, with no normalization, JSON, delimiters or terminators.
The `V1` domain already binds the transcript version: **do not prepend or append
an extra version byte to the signed transcript**. `SessionProof.Version` is a
separate internal value that verification requires to equal 1. Ed25519 signs
exactly the transcript; the signature is not part of its own signing input.
`SessionTranscript` returns caller-owned bytes and validates structure only.

## Bounds and exact credential binding

Each of the seven strings is 1..4096 bytes. Class is exactly `human`, `build_job`,
`model_worker`, or `service_account`. Credential hash, repository and session
must each be nonzero arrays of their stated size. Not-before must be positive;
expiry must be greater than not-before and at most 253402300799 (year 9999).
The interval is `[not_before, expiry)` and lasts at most 3600 seconds. Verification
also requires it to lie wholly within the authenticated identity credential's
validity interval. The implementation enforces
`len(sessionTranscript) + 64 + 1 <= 32768`; this size accounting does not define
an external serialized envelope or place the extra byte in the transcript.
Both credential and session signatures must be exactly 64 bytes.

The exact credential binding is:

```text
credentialHash = SHA256(identityTranscript || identitySignature)
sessionProofHash = SHA256(sessionTranscript || sessionSignature)
```

The identity transcript is literal `CANOPY\x00INTERNAL-IDENTITY\x00V1\x00`,
then five `u32be(byte_length) || raw_bytes` strings in order: issuer, key ID,
subject, class, audience; then signed 64-bit big-endian not-before and expiry
UTC Unix seconds. Its claims have the same string/class/time validity rules,
except no one-hour duration limit. Identity and session purposes are distinct.
`IdentityCredentialHash` checks bounded structure and signature length; it does
**not** verify a signature or authenticate the credential. A signing adapter
must authenticate independently before using that hash. `sessionProofHash` is
computed after successful verification and includes the signature; it is not
the session signing input. Knowing either digest establishes no permission.

## Verification and authority boundary

Trusted configuration supplies the identity resolver, exact audience, clocks,
identity revocation check, and issuer/key-ID maps of Ed25519 public keys.
Constructors copy trusted key bytes; a request cannot install/discover trust
roots. Issuer/key lookup, audience and the principal tuple are byte-exact.
`VerifySession` checks the session signature with the configured authority key,
resolves the identity credential (including its real signature, current time
and active revocation result), matches principal and audience, checks credential
hash and interval containment, then checks current session time and cancellation.
Missing, malformed, unknown, revoked, failed or indeterminate inputs/dependencies
fail closed with a zero verified value and `ErrUnauthenticated`.
A nil or canceled context is rejected; cancellation is checked after callbacks,
including clock/revocation callbacks. Inputs must not be concurrently mutated
by their transport owner; verification snapshots claims and signature slices
before invoking identity callbacks.

`VerifiedSession` has private verifier provenance. `Owns` establishes only that
this verifier produced the value, not current validity or authorization.
Verification does not durably enroll a credential/session, install context,
check current session enrollment/revocation or policy, grant a path/object,
or extend validity. The concrete authority must still establish protected
credential/session enrollment, revocation and current policy for each operation.
Repository/session IDs, generation and hashes alone are not bearer authority;
every object delivery still requires authorization.

## Existing reference vectors and evidence boundary

`TestSessionFrozenTranscriptAndClasses` fixes this literal transcript SHA-256:
`0c97743a8de9312c27dab0c05bc08db940ad5977df0e398819926c65c0c2889c`.
Its seven strings are `s`, `k`, `i`, `p`, `human`, `a`, `t`; credential hash is
`03` followed by 31 zero bytes, repository is `01` followed by 15 zero bytes,
session is `02` followed by 31 zero bytes, generation is 0, and times are 100/200.
This vector freezes transcript bytes, not a valid credential/signature pair.

### Complete signed fixture

The following complete vector is deterministic test data, not an issuer key or
credential for a real deployment. Hex values decode to raw bytes; all other
strings are the literal ASCII bytes shown. The session credential hash is the
`credential_hash_hex` value. The verifier uses Unix second 150, audience
`authority`, the two public keys below under their stated issuer/key IDs, and
an explicitly active identity-revocation fixture. The expected result is a
verified session with exactly these claims and `session_proof_hash_hex`.
That fixture result establishes neither durable enrollment nor policy rights.

```json
{
  "identity_seed_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "session_seed_hex": "6363636363636363636363636363636363636363636363636363636363636363",
  "identity_public_key_hex": "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
  "session_public_key_hex": "a7f6dfaf8f38b89ba8ce649b594f91e4d01fdc57f9c9493df43b5e50a9987367",
  "identity_claims": {
    "issuer": "issuer-A", "key_id": "key-1",
    "subject": "opaque-secret-subject", "principal_class": "human",
    "audience": "authority", "not_before_unix": 100, "expires_at_unix": 200
  },
  "identity_signature_hex": "a9afd982ddb18892a6f722bc53c2cd8be1d36c27bc5f9be06185d3f5b9ac99d80c5134c4fd25c01278733748519eb11019a3896caf5d867fcfb835f18698c800",
  "credential_hash_hex": "7398e14f066616f836e19b00e281079e2c72887ec0ae17ab5c00e01e74bca8df",
  "session_version": 1,
  "session_claims": {
    "authority_issuer": "session-issuer", "key_id": "session-key",
    "principal_issuer": "issuer-A", "principal_subject": "opaque-secret-subject",
    "principal_class": "human", "audience": "authority",
    "tenant_hex": "74656e616e7400ff",
    "repository_hex": "01000000000000000000000000000000",
    "session_hex": "0200000000000000000000000000000000000000000000000000000000000000",
    "generation": 0, "not_before_unix": 110, "expires_at_unix": 190
  },
  "session_signature_hex": "f3ca28cc2822fb713b1bc59d2b8f18713bc1c0bf53fbe73fd0e71bc42870bb745e6f0782df1d048d374f01ee3a84361f66211270c083799fa8ae9e16a1cc070c",
  "session_proof_hash_hex": "7e2269839a15c12ee1d768e6e617f1c4bfe0beb8a0ffe04511f04509ecc98549",
  "verifier_time_unix": 150
}
```

Reproduce it by framing the identity claims above, signing with the identity
seed, hashing that transcript and signature, then framing and signing the
session claims with the session seed. Hash the latter transcript and signature
for the proof hash. No JSON bytes or extra version byte enter either transcript.

`TestSessionAuthenticityAndProvenance` compares `SessionTranscript` against the
independent `sessionVector` framing and verifies real Ed25519 signatures and
proof hashes. Its identity seed is bytes 0..31; session seed is 32 copies of 99.
`TestIdentityIssuerScopeAndFraming` supplies a literal identity transcript.
`TestSessionRejectsClaimsAndSubstitutions`, `TestSessionClockAndKeySnapshot`,
`TestSessionSnapshotsBeforeIdentityCallback`, `TestSessionRejectsCrossAudienceIdentity`
and `TestIdentityCancellationDuringClockLookup` cover rejection/provenance
boundaries. These are local fixtures, not cloud, scale, public interoperability,
or durable authority evidence. This document adds no behavioral implementation.
