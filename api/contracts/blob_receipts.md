# Private blob ingest records v1 (#304)

This is a local internal storage contract, not an assertion about Anthropic
internals. `IngestStore` composes the existing canonical kind01 `Filesystem.Put`;
it adds no codec, public RPC, raw object delivery, graph result or publication.
A trusted offline operator creates an empty0700 root and calls
`InitializeIngestRoot`. It generates random32-byte identity, writes0400 metadata,
fsyncs the file and root, and returns that identity for pinning in trusted
configuration outside the root. Serving `OpenIngestStore` requires that exact
nonzero pin. It never creates a generation or adopts legacy blobs. Any init
failure after file creation returns zero plus `ErrOutcomeUnknown` and its cause;
a partially initialized root requires operator reprovisioning, never init retry.

The service launcher, ancestors, owner and exclusive root writer are trusted,
matching `Filesystem` assumptions. Same-UID/root and mount administrators are
outside this boundary. Lifetime nonblocking flock excludes cooperating owners;
0700 directories, owner/mode checks, confined roots, no-follow file opens and
root/directory identity checks protect private metadata. Constructor authority is
mandatory (including rejecting typed nil), fixed for the lifecycle, and checks
current principal/session/repository/purpose and visibility. Open checks before
root probes and before return; Put/Lookup check before metadata existence and
again before successful return. An authority implementation must be concurrency
safe and honor context deadlines. Neither an ID nor a record grants permission.
Only successful canonical validation and all `Filesystem.Put` durability barriers
permit record activation. The fixed163-byte0400 record binds version, generation,
full35-byte typed BlobID, full canonical length (payload+22), final file device,
inode, stored length, mtime, ctime and SHA256 of preceding metadata. It contains
no payload. `IngestRecord` is opaque and zero on every failure. Record activation
fsyncs temp, links without replacement, verifies exact existing proof on reuse,
fsyncs final, removes temp and fsyncs directory. Record/cleanup uncertainty retains
`ErrOutcomeUnknown` and underlying causes, including cancellation. Reuse repeats
barriers; a prior unknown result is never silently converted by EEXIST alone.
Lookup validates hash/type/generation/current file identity and completes final
record/file-directory barriers. Missing or failed proof fails closed without
fallback blob reads/rehashing. It returns no raw metadata or bytes.

Before serving, batched startup enumeration accounts all regular final files,
record temps and blob staging aliases, then completes existing blob-temp recovery.
Unknown names, unsafe entries or exhausted quotas make serving open fail. Accounting counts
logical stored file lengths, conservatively including hardlink aliases, excluding
fixed directory/filesystem overhead. Limits cap root bytes, blob entries, record
entries, concurrency and batch size. Each Put reserves two maximum encoded files
plus two records before disk I/O. Reservations remain charged even after success,
reuse or failure until reopen; admission may reject reuse at capacity. Reopen
reconstructs actual counts. Orphan records/temps remain charged and preserved;
this primitive has no collector. Only short accounting/lifecycle sections use a
mutex. Concurrent ingests perform disk I/O independently; no repository/global
sequencer is introduced. Close fails busy while operations run.

Stat is not fresh bitrot verification. These checks cannot detect an unannounced
snapshot rollback preserving the old generation and files. Destructive restore,
uncertain storage provenance or generation loss requires trusted external
invalidation/reprovisioning. Actual retained-generation registry, GC exclusion,
closure pins, transfer/recovery and resumable old-object adoption remain mandatory
before these records can satisfy TREE retention. A record is durable at-ingest
evidence only. Local tests do not prove process-kill, cloud or scale behavior.
