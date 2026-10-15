# Canonical objects and byte paths

**Candidate status:** director-approved v1 proposal for independent review. This is a proposed contract, not an accepted freeze or implemented capability. Ratification remains open under ADR-003/004 and the FND-03 review gate.

This contract defines immutable logical objects and repository path semantics. It does not define RPC serialization, storage envelopes, authorization, signatures as part of the object, or persistent tree pages.

## Canonical frame and typed IDs

All integers are fixed width, big-endian, with no varints, alignment padding, floats, maps, textual numbers, implicit defaults or unknown fields. `U8/U16/U32/U64` are unsigned; `I16/I64` are two's-complement signed. `B(x) = U32(byte_length(x)) || x`. `Opt(x) = 00` if absent or `01 || x` if present. No other option marker is valid.

```text
magic = 43 41 4e 4f 50 59 00 4f 42 4a 00  # ASCII CANOPY\0OBJ\0 (11 bytes)
C(kind, payload) = magic || U16(1) || U8(kind) || U64(len(payload)) || payload
D = SHA-256(C(kind, payload))                                      # 32 raw bytes
TID = U16(1) || U8(kind) || D                                     # exactly 35 bytes
```

Kind `01` is a raw blob. Kind `02` is a changeset. V1 accepts only these kinds. A parser rejects every unknown version or kind, including reserved future numbers; it never interprets an unknown object as a known one. Every embedded TID must have version 1 and the required kind. The canonical text spelling is exactly `^canopy:1:[0-9a-f]{2}:[0-9a-f]{64}$` for a registered v1 kind. The canonical parser rejects uppercase, whitespace, alternate widths and extra bytes. UI convenience parsing is separate and cannot participate in identity comparison.

A TID's version and kind must equal the frame header. IDs identify uncompressed canonical bytes only. The same logical bytes under different storage codecs have the same TID. A digest is an identifier, not permission to read or write an object.

## V1 payloads

A blob payload is its exact raw byte sequence. Empty blobs, NUL bytes and invalid UTF-8 are valid. Blob payloads have no repository ID, allowing physical deduplication without granting cross-repository access.

A changeset payload is exactly the following sequence, with no trailing bytes:

```text
repo_id[16]
U32(parent_count) || TID(parent_0) ... TID(parent_n-1)
B(author_identity_bytes) || I64(author_unix_seconds) || I16(author_offset_minutes)
Opt(B(committer_identity_bytes) || I64(committer_unix_seconds) || I16(committer_offset_minutes))
B(message_bytes)
Opt(B(declared_message_encoding_bytes))
U32(operation_count) || operation_0 ... operation_n-1

operation = B(path_bytes) || U8(tag) || target_when_required
00 = DELETE           # no target bytes
01 = SET_REGULAR      # kind-01 blob TID; native mode 100644 octal
02 = SET_EXECUTABLE   # kind-01 blob TID; native mode 100755 octal
03 = SET_SYMLINK      # kind-01 blob TID; native mode 120000 octal
```

`repo_id` is an opaque 16-byte identity, not a repository name; zero bytes are valid in synthetic vectors. Author and committer identities, message, and declared encoding are opaque exact bytes, not UTF-8/email/parser requirements. Empty values are valid. Present-empty differs from absent for both optional fields. Seconds are Unix UTC seconds. Offset is a signed count of minutes east of UTC in `[-1439, 1439]`; it is identity-bearing declared metadata and is not applied a second time to the instant. There is no leap-second or fractional-second representation. Encoding labels are declarations and never authorize transcoding message bytes.

Every listed field is part of the changeset ID. Parent order, operation order, modes, metadata, timestamp offsets, message bytes, and option presence are identity-bearing. There is no server timestamp, ref, publication ID, request/idempotency key, ACL, credential, trace field, codec, signature or verification result in the canonical payload. Preserve these external records separately. The encoder must not invent omitted-field defaults or rewrite declared bytes.

## Parent and path rules

Parent TIDs are kind `02` changesets in the same repository and must be durably published before this changeset. Preserve the supplied sequence exactly: parent zero is the tree base; additional parents establish ancestry and do not implicitly union trees. Do not sort or deduplicate the sequence. Repeated IDs are permitted as source-faithful sequence data; graph work may deduplicate its traversal within explicit work budgets. A root changeset has zero parents and starts from the empty tree.

Paths are byte strings, never Unicode strings at an API boundary. Byte `2f` is the only separator. A path is relative and nonempty. Reject NUL, a leading or trailing slash, empty components, and any exact component `.` or `..`. Sort by unsigned lexicographic order of the complete raw path, with a shorter exact prefix first. Operations must be strictly increasing in this order; duplicate full paths and stored out-of-order operations are invalid. An input-map encoder may sort only when its API explicitly declares that conversion; a parser never repairs order.

All other bytes are literal: `ff` is valid; backslash is an ordinary byte, not a separator; percent sequences are not decoded; case and Unicode normalization are not changed. Thus `A` and `a`, UTF-8 NFC `c3 a9`, UTF-8 NFD `65 cc 81`, and a name containing `ff` are distinct paths. Do not normalize names for lookup, storage, equality, sorting or authorization. Display escaping must be reversible and cannot be fed back as a path without an explicit inverse conversion. Do not impose a host filesystem's component limit on the repository namespace.

The three set tags are distinct even when they reference the same blob. A symlink's blob is exact link-content bytes; canonical parsing does not resolve it or apply host syntax. Checkout must separately reject unsafe/unrepresentable links, operate relative to a no-follow workspace root and prevent a symlink from redirecting later path writes outside that root. Report host case/normalization collisions, reserved names and unsupported names before writing; do not mutate stored repository paths to make them fit.

## Changeset application

Operations are a simultaneous delta against the first parent's tree (or the empty tree for a root), never a sequential program whose result depends on encoded order. `DELETE` removes only an exact tracked leaf. Deleting an absent leaf is a valid no-op and remains in the changeset hash. Deleting a directory is not recursive; implicit directories are not tracked leaves. A `SET` replaces the exact leaf at its path and creates implicit directory ancestors.

After applying the complete delta, tracked leaf paths must be prefix-free: no leaf may also be an ancestor of another leaf. Validate this final state, not every operation-prefix pair. For example, `DELETE a` plus `SET a/b` may replace a base file with a directory; `DELETE a/b` plus `SET a` may replace a populated directory only when every conflicting descendant leaf is explicitly removed. A partial removal fails. `SET a` plus `SET a/b` fails. Conflicting final trees fail independent of serialized operation order. Empty directories have no v1 representation.

Concrete tree-application fixtures (not tree-object IDs; v1 has no tree object): (1) base `{a: blob-X}`, delta `[DELETE a, SET a/b: blob-X]` yields `{a/b: blob-X}`; (2) base `{a/b: blob-X, a/c: blob-X}`, delta `[SET a: blob-X, DELETE a/b, DELETE a/c]` yields `{a: blob-X}`; removing only `a/b` in fixture (2) fails; (3) empty base with `DELETE a` yields the empty tree; (4) empty base with `SET a` and `SET a/b` fails. These fixtures use logical leaf maps and do not prescribe a persistent tree encoding.

## Bounds and strict parsing

These are v1 format maxima, not measured capacity or grounds to exclude larger required inputs. Keep any required over-limit source as an explicit blocker until the format is amended or the owner excludes it.

| Field/work | V1 maximum |
|---|---:|
| Blob payload | `2^40` bytes, stream-processed |
| Entire changeset payload | 64 MiB |
| Parent count | 1,024 |
| Operation count | 1,000,000, additionally bounded by 64 MiB payload |
| Path | 1..65,535 bytes; at most 1,024 components |
| Each author/committer identity | 65,536 bytes |
| Message | 16 MiB |
| Encoding declaration | 256 bytes |

Reject over-limit sizes/counts, malformed or mismatched typed IDs, wrong parent/target kinds, unknown tags, missing SET targets, DELETE targets, invalid paths/order, bad offsets, option markers other than `00/01`, truncation, declared-length mismatch, trailing bytes, unknown canonical fields, and arithmetic overflow. Check count/length against remaining bytes before allocation; never size an allocation from an unchecked count. Streaming parsers enforce object, byte, work and depth budgets before exposing verified data. An existing object at a TID must be decoded and rehashed; mismatching bytes are corruption, never overwrite permission.

## Transport and signatures are separate

Store/RPC envelopes version and identify codecs separately from the canonical frame. After bounded decompression, require the exact declared canonical length, one complete frame, no trailing bytes and the expected typed digest. Unknown codecs/envelope versions, truncation, excessive decoder windows/expansion, frame/object count excess, incomplete transfers and resource exhaustion fail closed; no partial or compressed-checksum-only object is verified. FND-05/OBJ-04 must freeze codec, envelope, decoder-window, expansion-ratio, byte, range and resume limits. A codec's representation never changes the TID. Until those contracts select concrete codecs, the transport conformance fixture is: any two distinct envelopes they authorize that decode exactly to a listed canonical preimage must yield that row's same TID; envelope bytes are intentionally not canonical vectors here.

Preserve the exact original source object bytes as a raw blob. A separate append-only, versioned source/native mapping binds repository, native changeset TID, source system, source object kind, source hash algorithm and exact source object ID, raw-source blob TID, and source-signature evidence. Retry cannot silently retarget the mapping or replace its verification provenance. Keep source signature bytes or spans tied to those exact source bytes. A `SOURCE_GIT` signature verifies only the source-format signing payload; it is never proof that native canonical bytes were signed. Importers must preserve lexical source evidence (for example original offset spelling, extra headers or identifier spelling) and cannot claim lossless equivalence after discarding it.

A native detached authorship signature is an external, versioned attestation naming its target TID and a separate native purpose. The candidate exact signed transcript is ASCII `CANOPY\0NATIVE-SIGNATURE\0` followed by the target's 35-byte TID; for the root-A vector below the transcript hex is `43414e4f5059004e41544956452d5349474e415455524500000102f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee`. This domain is only for native object authorship, not review, landing or CI. Signature scheme, key identity/trust and verification policy remain a separate trust-contract decision; this transcript proposal alone does not establish native signature support. Adding/removing a detached signature does not change the target ID or form a hash cycle. A Git source signature and a native signature are different classes and cannot substitute for one another.

## Git migration boundary and projections

LFS pointers are literal file bytes; do not dereference them. V1 has no gitlink/submodule or empty-directory operation. On encountering any such entry in the migration scope, the importer must preserve source identity/raw evidence, emit a durable unsupported-input manifest with source object and path/mode provenance, and block the corresponding migration acceptance. It must not drop, flatten, reinterpret or mark the full-scope requirement optional. Supporting these entries requires an explicit director-approved contract amendment, exact encoding and new vectors. Other unrepresentable Git metadata or modes also remain visible migration blockers until a declared fidelity policy resolves them.

A raw changeset contains every changed path and blob ID. A restricted reader must receive it only with authorization for the full raw object and every disclosed field/path, or receive a distinct projected changeset/view representation. A projection has its own identity bound to source revision, view/policy/selection and projection algorithm; it must never masquerade as the source's canonical bytes, native TID, or signed source payload. Parent/history identity, message/author visibility and hidden ancestors require the security/query contract. This aligns raw byte-path semantics with the separate security contract.

## Byte-exact positive vectors

Each row gives the complete `C(kind,payload)` preimage as continuous lowercase hex and the expected SHA-256 digest `D`. Values are reproducible with `evidence/FND-03/attempt-1/canonical-vectors.py`; the script reconstructs the bytes and checks both the listed digest and this table. For changesets, shared defaults are repo ID `00` x16, author `41` (`A`), author seconds/offset zero, absent committer and encoding, empty message unless stated, and empty operations unless stated. `X` is blob payload `78`; embedded IDs are full 35-byte TIDs.

| Vector | Complete canonical preimage hex | Expected SHA-256 |
|---|---|---|
| blob_empty | `43414e4f5059004f424a000001010000000000000000` | `d300c179fc91e6df3575c746e504ce7edbfa118fae5cb3446df7696157cc7235` |
| blob_x | `43414e4f5059004f424a00000101000000000000000178` | `b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052` |
| root_A_message_ff | `43414e4f5059004f424a00000102000000000000002e00000000000000000000000000000000000000000000000141000000000000000000000000000001ff0000000000` | `f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee` |
| nonutf8_ff_executable_parent_A | `43414e4f5059004f424a0000010200000000000000790000000000000000000000000000000000000001000102f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee0000000141000000000000000000000000000000000000000100000001ff02000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052` | `438a09a6c4a38f09730804074b557ff0dedc2c9f221dbaa2ee748e1d51ee9f42` |
| delete_ff_parent_B | `43414e4f5059004f424a0000010200000000000000560000000000000000000000000000000000000001000102438a09a6c4a38f09730804074b557ff0dedc2c9f221dbaa2ee748e1d51ee9f420000000141000000000000000000000000000000000000000100000001ff00` | `457753f4dace3d206e1d5c10747150a56dcdace4ed1cbff8b967b7749cad0c0e` |
| noop_delete_ff_root | `43414e4f5059004f424a00000102000000000000003300000000000000000000000000000000000000000000000141000000000000000000000000000000000000000100000001ff00` | `865a4926c0b0f2a725f6abf809fbb4bd0416f55e47f86f155a6a77982433f1a1` |
| parent_order_AB | `43414e4f5059004f424a0000010200000000000000730000000000000000000000000000000000000002000102f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee000102438a09a6c4a38f09730804074b557ff0dedc2c9f221dbaa2ee748e1d51ee9f4200000001410000000000000000000000000000000000000000` | `1aabe967540700974c3eeafda5af257ad151682ed1f314bfd55eb5fb7f144a48` |
| parent_order_BA | `43414e4f5059004f424a0000010200000000000000730000000000000000000000000000000000000002000102438a09a6c4a38f09730804074b557ff0dedc2c9f221dbaa2ee748e1d51ee9f42000102f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee00000001410000000000000000000000000000000000000000` | `b10bb307ff4ea79466f5901327d8ae4c26ca7c64eb3552417bbcbce02594c2bb` |
| mode_regular | `43414e4f5059004f424a000001020000000000000056000000000000000000000000000000000000000000000001410000000000000000000000000000000000000001000000016601000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052` | `594def650a507241fe608a4a58210f33f64cf1c84243285278c5b0b126c120fb` |
| mode_executable | `43414e4f5059004f424a000001020000000000000056000000000000000000000000000000000000000000000001410000000000000000000000000000000000000001000000016602000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052` | `192d9db24fcf992a334faddd1cf50545e1f7dd0487c0ca0198500cfa29fd2892` |
| mode_symlink | `43414e4f5059004f424a000001020000000000000056000000000000000000000000000000000000000000000001410000000000000000000000000000000000000001000000016603000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052` | `30913c27f5af231c48b2ee3e9cb800d9d9066e772649a754d1a982f0f085cb6d` |
| metadata_absent | `43414e4f5059004f424a00000102000000000000002d000000000000000000000000000000000000000000000001410000000000000000000000000000000000000000` | `bdee982b0f3b4bfff9ef151f81d8578a5afd3022c07ef86b7883f848c0944d89` |
| committer_present_empty | `43414e4f5059004f424a00000102000000000000003b0000000000000000000000000000000000000000000000014100000000000000000000010000000000000000000000000000000000000000000000` | `ff4c76d67982d119dc6bcb37c173a816a889350b532f47cb68fa07cdafa7a9fc` |
| encoding_present_empty | `43414e4f5059004f424a00000102000000000000003100000000000000000000000000000000000000000000000141000000000000000000000000000000010000000000000000` | `7da5e70435d6596a98808bafb53908a594f2cdc921426b99dd31b69831770060` |
| metadata_full_offsets | `43414e4f5059004f424a00000102000000000000004600000000000000000000000000000000000000000000000141000000006553f100014a010000000143000000006553f107fed4000000016d01000000057574662d3800000000` | `5cd0226da8c40d20f5e2f43212e2782bc07ddaf2c1eb98fad0b823da454cd642` |
| path_A_upper | `43414e4f5059004f424a000001020000000000000056000000000000000000000000000000000000000000000001410000000000000000000000000000000000000001000000014101000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052` | `d419c81c623636a49469b804368e2f2ead8e88ce08f15b449b51c992304b65d4` |
| path_a_lower | `43414e4f5059004f424a000001020000000000000056000000000000000000000000000000000000000000000001410000000000000000000000000000000000000001000000016101000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052` | `5c6d8c08e97604286ccb52fd54b4ac60a153b8fdff26e33ede8cf49f9cdb4acb` |
| path_nfc_e_acute | `43414e4f5059004f424a00000102000000000000005700000000000000000000000000000000000000000000000141000000000000000000000000000000000000000100000002c3a901000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052` | `96acac1b45deb2f39f0c162a6c0264c1b41d4957c92e7031ea8abca8946ab8a9` |
| path_nfd_e_acute | `43414e4f5059004f424a0000010200000000000000580000000000000000000000000000000000000000000000014100000000000000000000000000000000000000010000000365cc8101000101b549a630683504c9f8eed1ff0b23e54e18895c14188ecac1cba6a1a44da02052` | `60ec419c01dac21dc6aa04dd4db8122fc48a53594746d5c6a7c7a5b215adc271` |

The vectors show that the executable change uses the valid non-UTF-8 path byte `ff`; the next vector explicitly deletes that byte path. All three mode tags, option-presence differences, signed offsets, path case/normalization distinctions and parent reversal change the expected ID. The transport metamorphic fixture is described above because its permitted envelope bytes are owned by FND-05, not this canonical payload format.

## Negative and positive semantic fixtures

Reject paths with hex `''`, `00`, `2f61`, `612f`, `612f2f62`, `2e`, `2e2e`, `612f2e2f62`, or `612f2e2e2f62`. Accept `5c` and literal bytes `%2e%2e`; neither is normalized into a separator or dot component. Reject operation lists `[62,61]` (out of order), `[61,61]` (duplicate path), two SETs at `61` and `612f62` (final leaf conflict), or a file replacement leaving any conflicting descendant. Accept sorted DELETE `61` plus SET `612f62` over a base file at `61`.

Also reject SET without a target, SET to a non-blob or wrong-version TID, unknown tag, DELETE with target bytes, a blob ID among parents, reversed canonical operation order, unknown kind/version, option marker `02`, malformed TID, truncated or overlong frame, count/length overflow, excess bounds, incomplete count data, trailing bytes and offsets `+1440/-1440`. Same-TID bytes that mutate or mismatch the declared type are corruption. Raw versus any two permitted compressed envelopes must recover the same TID; truncation or over-budget expansion cannot expose a verified object. Reject using SOURCE_GIT evidence as a native signature, changing native bytes under a prior target signature, retargeting a source/native map on retry, or claiming source verification without exact raw-source evidence. Checkout reports collisions and symlink/path escape risks before writes without altering repository path bytes.

## Future persistent trees

V1 intentionally defines no tree/page object kind and no flat full-root manifest in a changeset. Keep `(repo, changeset, index-kind, algorithm-version) -> derived tree/page TID` separate. A later bounded persistent-page encoding requires its own frozen schema, deterministic construction, empty/root representation, incremental update and structural-sharing rules, limits, and vectors before implementation. A one-entry edit in a million-entry directory must not reserialize, hash, scan, fetch or rewrite that whole directory. Reserving a future kind is not support for that kind or permission to ship an unbounded flat list.
