package metadata

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"

	"canopy.local/canopy/internal/model"
)

// These are conservative application admission limits, not claims about Spanner
// service quotas or measured capacity. Canonical objects stay in durable object
// storage; publication rows contain identities and bounded parent metadata only.
const (
	SpannerSchemaVersion                  = 1
	SpannerMaxOpaqueBytes                 = 128
	SpannerMaxPrincipalBytes              = 1024
	SpannerMaxMutationBytes               = 1024
	SpannerMaxRefBytes                    = 1024
	SpannerMaxRowBytes             uint64 = 256 << 10
	SpannerMaxKeyBytes             uint64 = 4096
	SpannerMaxTransactionBytes     uint64 = 512 << 10
	SpannerMaxTransactionCells     uint64 = 128
	SpannerMaxPublicationRows      uint64 = 4
	SpannerMaxPublicationReads     uint64 = model.MaxParents + 3
	SpannerMaxReadRowBytes         uint64 = 4096
	SpannerMaxPublicationReadBytes uint64 = SpannerMaxPublicationReads * SpannerMaxReadRowBytes
	SpannerOutboxShards                   = 256
)

// Provider key-column limit; independent of application byte/row budgets.
// https://docs.cloud.google.com/spanner/quotas#indexes
const SpannerMaxKeyColumns = 16

type SpannerType uint8

const (
	SpannerBytes SpannerType = iota + 1
	SpannerInt64
	SpannerBool
)

// Semantics describe values, independently of column spelling. Review rejects
// repository prefixes, timestamps/counters and opaque sequential IDs as leading
// keys, including indexes. Hash/shard columns are SHA-256 of HashOf's complete,
// length-framed values, with a versioned table domain; never raw TID prefixes.
type SpannerSemantic uint8

const (
	SpannerIdentity SpannerSemantic = iota + 1
	SpannerRepository
	SpannerSequential
	SpannerHash
	SpannerShard
	SpannerValue
	SpannerCanonicalPayload
)

type SpannerColumn struct {
	Name     string
	Type     SpannerType
	MaxBytes uint64 // BYTES length, zero is invalid (MAX is never permitted)
	Semantic SpannerSemantic
	HashOf   []string
}
type SpannerIndex struct {
	Name   string
	Key    []string
	Unique bool
}
type SpannerTable struct {
	Name       string
	Columns    []SpannerColumn
	PrimaryKey []string
	Indexes    []SpannerIndex
	Immutable  bool
}
type SpannerSchemaDefinition struct{ Tables []SpannerTable }
type SpannerSchemaIssue struct{ Table, Key, Reason string }

func scBytes(name string, n uint64, semantic SpannerSemantic) SpannerColumn {
	return SpannerColumn{Name: name, Type: SpannerBytes, MaxBytes: n, Semantic: semantic}
}
func scHash(name string, fields ...string) SpannerColumn {
	return SpannerColumn{Name: name, Type: SpannerBytes, MaxBytes: 32, Semantic: SpannerHash, HashOf: fields}
}

// SpannerSchema returns a fresh owned definition. EventBindings has no expiry or
// acknowledgement column: (repository,event) survives outbox acknowledgement.
// No interleaving under one repository row, global sequence or ref dependency is
// used. Secondary indexes distribute writes too; outbox listing uses a bounded
// 256-shard, repository-scoped snapshot/cursor merge, not a time-ordered leader.
func SpannerSchema() SpannerSchemaDefinition {
	repo := func() SpannerColumn { return scBytes("Repository", 16, SpannerRepository) }
	change := func() SpannerColumn { return scBytes("Changeset", model.TypedIDSize, SpannerIdentity) }
	opaque := func(n string) SpannerColumn { return scBytes(n, SpannerMaxOpaqueBytes, SpannerIdentity) }
	return SpannerSchemaDefinition{Tables: []SpannerTable{
		{Name: "Publications", Immutable: true, PrimaryKey: []string{"Route", "Repository", "Changeset"}, Columns: []SpannerColumn{
			scHash("Route", "Repository", "Changeset"), repo(), change(), opaque("Publication"), opaque("Event"),
			scHash("PublicationRoute", "Repository", "Publication"),
			scBytes("Parents", 4+model.MaxParents*model.TypedIDSize, SpannerValue),
			{Name: "PayloadBytes", Type: SpannerInt64, Semantic: SpannerValue},
		}, Indexes: []SpannerIndex{{Name: "PublicationsByID", Key: []string{"PublicationRoute", "Repository", "Publication"}, Unique: true}}},
		{Name: "EventBindings", Immutable: true, PrimaryKey: []string{"Route", "Repository", "Event"}, Columns: []SpannerColumn{
			scHash("Route", "Repository", "Event"), repo(), opaque("Event"), change(), opaque("Publication"),
		}},
		{Name: "MutationResults", Immutable: true, PrimaryKey: []string{"Route", "Repository", "Principal", "Operation", "Mutation"}, Columns: []SpannerColumn{
			scHash("Route", "Repository", "Principal", "Operation", "Mutation"), repo(), scBytes("Principal", SpannerMaxPrincipalBytes, SpannerIdentity),
			scBytes("Operation", 1, SpannerIdentity), scBytes("Mutation", SpannerMaxMutationBytes, SpannerIdentity),
			scBytes("RequestDigest", 32, SpannerValue), scBytes("Result", 512, SpannerValue),
			{Name: "ExpiresAt", Type: SpannerInt64, Semantic: SpannerSequential},
		}},
		{Name: "Outbox", PrimaryKey: []string{"Route", "Repository", "Event"}, Columns: []SpannerColumn{
			scHash("Route", "Repository", "Event"), repo(), opaque("Event"), change(), opaque("Publication"),
			{Name: "Shard", Type: SpannerInt64, Semantic: SpannerShard, HashOf: []string{"Repository", "Event"}},
			{Name: "Acknowledged", Type: SpannerBool, Semantic: SpannerValue},
		}, Indexes: []SpannerIndex{{Name: "OutboxPending", Key: []string{"Shard", "Repository", "Acknowledged", "Route", "Event"}}}},
		{Name: "Refs", PrimaryKey: []string{"Route", "Repository", "Name"}, Columns: []SpannerColumn{
			scHash("Route", "Repository", "Name"), repo(), scBytes("Name", SpannerMaxRefBytes, SpannerIdentity),
			scBytes("Target", model.TypedIDSize, SpannerValue),
			// Fixed U64BE preserves the port's entire uint64 generation range.
			scBytes("Generation", 8, SpannerValue),
		}},
		{Name: "DerivedMappings", Immutable: true, PrimaryKey: []string{"Route", "Repository", "Changeset", "Kind", "Version"}, Columns: []SpannerColumn{
			scHash("Route", "Repository", "Changeset", "Kind", "Version"), repo(), change(), opaque("Kind"),
			{Name: "Version", Type: SpannerInt64, Semantic: SpannerIdentity}, scBytes("Value", 39, SpannerValue),
			// U32 count, then ordered (repo[16],TID[35],B(kind),U32 version,value[39]).
			// Parent kinds/versions may differ as declared by the registered algorithm.
			scBytes("Parents", 4+model.MaxParents*(16+35+4+SpannerMaxOpaqueBytes+4+39), SpannerValue),
		}},
	}}
}

var spannerIdentifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

func columnSize(c SpannerColumn) uint64 {
	switch c.Type {
	case SpannerBytes:
		return c.MaxBytes
	case SpannerInt64:
		return 8
	case SpannerBool:
		return 1
	}
	return 0
}

// ReviewSpannerSchema checks structure, semantic key distribution, bounded types,
// row/key bytes and index amplification. Renaming a timestamp or payload cannot
// evade these checks. It does not inspect a deployed database or authorize DDL.
func ReviewSpannerSchema(s SpannerSchemaDefinition) []SpannerSchemaIssue {
	var issues []SpannerSchemaIssue
	add := func(table, key, reason string) { issues = append(issues, SpannerSchemaIssue{table, key, reason}) }
	names := map[string]bool{}
	tables := map[string]bool{}
	required := map[string]SpannerTable{}
	for _, t := range SpannerSchema().Tables {
		required[t.Name] = t
	}
	if len(s.Tables) == 0 {
		add("", "", "empty schema")
	}
	for _, t := range s.Tables {
		tables[t.Name] = true
		if !spannerIdentifier.MatchString(t.Name) || names[strings.ToLower(t.Name)] {
			add(t.Name, "", "invalid or duplicate table")
		}
		names[strings.ToLower(t.Name)] = true
		columns := map[string]SpannerColumn{}
		columnNames := map[string]bool{} // Identifiers are ASCII; references stay exact.
		var row uint64
		for _, c := range t.Columns {
			if !spannerIdentifier.MatchString(c.Name) {
				add(t.Name, c.Name, "invalid column")
			}
			if columnNames[strings.ToLower(c.Name)] {
				add(t.Name, c.Name, "duplicate column")
			}
			columnNames[strings.ToLower(c.Name)] = true
			columns[c.Name] = c
			n := columnSize(c)
			if n == 0 || n > SpannerMaxRowBytes || row > SpannerMaxRowBytes || n+16 > SpannerMaxRowBytes-row {
				add(t.Name, c.Name, "unbounded or oversized row/type")
			} else {
				row += n + 16
			}
			if c.Type != SpannerBytes && c.MaxBytes != 0 {
				add(t.Name, c.Name, "byte bound on non-byte type")
			}
			if c.Semantic < SpannerIdentity || c.Semantic > SpannerCanonicalPayload {
				add(t.Name, c.Name, "unknown semantics")
			}
			if c.Semantic == SpannerCanonicalPayload {
				add(t.Name, c.Name, "canonical payload belongs in object storage")
			}
			if c.Semantic == SpannerHash || c.Semantic == SpannerShard {
				if c.Semantic == SpannerHash && (c.Type != SpannerBytes || c.MaxBytes != 32) || c.Semantic == SpannerShard && c.Type != SpannerInt64 {
					add(t.Name, c.Name, "invalid hash/shard representation")
				}
			} else if len(c.HashOf) != 0 {
				add(t.Name, c.Name, "hash inputs on non-hash column")
			}
		}
		// Required v1 representations must still hold every admitted port value.
		// Additional fields remain subject to the same row/key/write limits.
		for _, want := range required[t.Name].Columns {
			got, ok := columns[want.Name]
			if !ok || got.Type != want.Type || got.MaxBytes != want.MaxBytes || got.Semantic != want.Semantic || !slices.Equal(got.HashOf, want.HashOf) {
				add(t.Name, want.Name, "missing or incompatible required column")
			}
		}
		// The v1 helpers and publication plans emit fixed named key columns.
		// A different distributed key is not interchangeable with that identity.
		if want, ok := required[t.Name]; ok {
			if !slices.Equal(t.PrimaryKey, want.PrimaryKey) {
				add(t.Name, "PRIMARY KEY", "missing or incompatible required primary key")
			}
			for _, index := range want.Indexes {
				found := false
				for _, got := range t.Indexes {
					if got.Name == index.Name && got.Unique == index.Unique && slices.Equal(got.Key, index.Key) {
						found = true
					}
				}
				if !found {
					add(t.Name, index.Name, "missing or incompatible required index")
				}
			}
		}
		validRoutes := map[string]bool{}
		for _, c := range t.Columns {
			if c.Semantic != SpannerHash && c.Semantic != SpannerShard {
				continue
			}
			hasIdentity, hasRepo := false, false
			valid := c.Semantic == SpannerHash && c.Type == SpannerBytes && c.MaxBytes == 32 || c.Semantic == SpannerShard && c.Type == SpannerInt64 && c.MaxBytes == 0
			seen := map[string]bool{}
			for _, f := range c.HashOf {
				v, ok := columns[f]
				if !ok || seen[f] || (v.Semantic != SpannerIdentity && v.Semantic != SpannerRepository) {
					valid = false
					add(t.Name, c.Name, "invalid hash input")
				}
				seen[f] = true
				hasIdentity = hasIdentity || ok && v.Semantic == SpannerIdentity
				hasRepo = hasRepo || ok && v.Semantic == SpannerRepository
			}
			if !hasIdentity || !hasRepo {
				add(t.Name, c.Name, "hash must include repository and varying identity")
			}
			validRoutes[c.Name] = valid && hasIdentity && hasRepo
		}
		checkKey := func(name string, key []string, primary, unique bool) {
			if len(key) == 0 {
				add(t.Name, name, "empty key")
				return
			}
			lead, ok := columns[key[0]]
			if !ok || lead.Semantic != SpannerHash && lead.Semantic != SpannerShard || primary && lead.Semantic != SpannerHash {
				add(t.Name, name, "leading key is not distributed")
			}
			seen := map[string]bool{}
			for _, f := range key {
				_, exists := columns[f]
				if !exists || seen[f] {
					add(t.Name, name, "missing or duplicate key column")
				}
				seen[f] = true
			}
			// Spanner appends missing PK columns to secondary physical keys. Size
			// those too, once each, without changing the declared lookup identity.
			physical := append([]string(nil), key...)
			if !primary {
				for _, f := range t.PrimaryKey {
					if !slices.Contains(physical, f) {
						physical = append(physical, f)
					}
				}
			}
			if len(physical) > SpannerMaxKeyColumns {
				add(t.Name, name, "too many physical key columns")
			}
			var size uint64
			for _, f := range physical {
				n := columnSize(columns[f])
				if n > SpannerMaxKeyBytes-16 || size > SpannerMaxKeyBytes-(n+16) {
					add(t.Name, name, "oversized key")
				} else {
					size += n + 16
				}
			}
			if !seen["Repository"] {
				add(t.Name, name, "key lacks repository scope")
			}
			// Keep full inputs alongside the hash, so a hash collision cannot alias an
			// identity or relax uniqueness. Hashes route; they are not bearer IDs.
			for _, f := range lead.HashOf {
				if !seen[f] {
					add(t.Name, name, "key drops full hash input")
				}
			}
			// Nonunique indexes can have arbitrarily many rows sharing the
			// declared key. Their implicit PK identities must be routed too.
			// Unique indexes may omit implicit PK identities only when their
			// declared suffix cannot create unrestricted multiplicity before a
			// complete route. PublicationsByID need not hash implicit Changeset.
			identityKey := key
			if !primary && !unique {
				identityKey = physical
			}
			for _, f := range identityKey[1:] {
				// Identity labels must be hashed; unrestricted Value suffixes also
				// need a complete row/lookup route, checked in physical order below.
				if primary || columns[f].Semantic == SpannerIdentity || columns[f].Semantic == SpannerRepository {
					found := false
					for _, input := range lead.HashOf {
						found = found || input == f
					}
					if !found {
						add(t.Name, name, "routing hash omits logical key field")
					}
				}
			}
			// A sequential component can itself distinguish unbounded rows even
			// in a UNIQUE index. Before that append edge, require a full hash of
			// the physical row identities. A finite shard or Operation-only hash
			// is insufficient; a complete Route appearing later cannot repair it.
			rowDistributed := false
			lookupDistributed := false
			// The supported pre-route shape has at most one independent Bool
			// Value. Saturate at excess; never compute a product or shift by N.
			boolDimension, boolExcess := "", false
			for _, f := range physical {
				c := columns[f]
				if c.Semantic == SpannerSequential && !rowDistributed {
					add(t.Name, name, "sequential key precedes distributed row identity")
				}
				if c.Semantic == SpannerValue && c.Type != SpannerBool && !rowDistributed && !lookupDistributed {
					add(t.Name, name, "unrestricted value precedes distributed row or lookup identity")
				}
				if c.Semantic == SpannerValue && c.Type == SpannerBool && !rowDistributed && !lookupDistributed {
					if boolDimension == "" {
						boolDimension = f
					} else if boolDimension != f && !boolExcess {
						boolExcess = true
						add(t.Name, name, "multiple Boolean dimensions precede distributed row or bounded lookup identity")
					}
				}
				if c.Semantic == SpannerHash && validRoutes[f] {
					complete := true
					for _, identity := range physical {
						semantic := columns[identity].Semantic
						if (semantic == SpannerIdentity || semantic == SpannerRepository) && !slices.Contains(c.HashOf, identity) {
							complete = false
						}
					}
					rowDistributed = rowDistributed || complete
					// A separately enforced UNIQUE lookup can also bound rows per
					// route (e.g. PublicationsByID). Every varying component must be
					// determined by this hash's full inputs. Unrestricted Values or
					// sequential components cannot certify their own multiplicity.
					for _, lookup := range t.Indexes {
						if !lookup.Unique || len(lookup.Key) == 0 {
							continue
						}
						complete := spannerIdentifier.MatchString(lookup.Name) && validRoutes[lookup.Key[0]]
						lookupColumns := len(lookup.Key)
						for _, field := range t.PrimaryKey {
							if !slices.Contains(lookup.Key, field) {
								lookupColumns++
							}
						}
						complete = complete && lookupColumns <= SpannerMaxKeyColumns
						lookupBool := ""
						lookupFields := map[string]bool{}
						for _, field := range lookup.Key {
							complete = complete && !lookupFields[field]
							lookupFields[field] = true
							part := columns[field]
							switch part.Semantic {
							case SpannerIdentity, SpannerRepository:
								complete = complete && slices.Contains(c.HashOf, field) && slices.Contains(physical, field)
							case SpannerHash, SpannerShard:
								complete = complete && validRoutes[field]
								for _, input := range part.HashOf {
									complete = complete && slices.Contains(c.HashOf, input) && slices.Contains(physical, input) && slices.Contains(lookup.Key, input)
								}
							case SpannerValue:
								complete = complete && part.Type == SpannerBool && (lookupBool == "" || lookupBool == field)
								lookupBool = field
							default:
								complete = false
							}
						}
						// One eligible lookup caps ALL rows per hash-input tuple
						// at two; later Bool fields do not multiply that bound.
						lookupDistributed = lookupDistributed || complete && lookupFields["Repository"]
					}
				}
			}
		}
		checkKey("PRIMARY KEY", t.PrimaryKey, true, true)
		for _, idx := range t.Indexes {
			if !spannerIdentifier.MatchString(idx.Name) || names[strings.ToLower(idx.Name)] {
				add(t.Name, idx.Name, "invalid or duplicate index")
			}
			names[strings.ToLower(idx.Name)] = true
			checkKey(idx.Name, idx.Key, false, idx.Unique)
		}
	}
	for _, required := range []string{"Publications", "EventBindings", "MutationResults", "Outbox", "Refs", "DerivedMappings"} {
		if !tables[required] {
			add(required, "", "missing required metadata table")
		}
	}
	// A new publication writes these four rows in ONE atomic transaction. Include
	// index cells/bytes conservatively; adding an index must not silently grow it.
	budget, err := spannerPublicationBudget(s)
	if err != nil || budget.Rows != SpannerMaxPublicationRows || budget.Cells > SpannerMaxTransactionCells || budget.Bytes > SpannerMaxTransactionBytes {
		add("Publications", "transaction", "publication mutation budget exceeded or missing table")
	}
	return issues
}

// SpannerDDL emits GoogleSQL definitions from the same checked descriptors.
// All columns are required; runtime row encoders must enforce exact fixed widths,
// version/type validation, shard derivation and integer ranges before admission.
func SpannerDDL(s SpannerSchemaDefinition) ([]string, error) {
	if len(ReviewSpannerSchema(s)) != 0 {
		return nil, ErrInvalidArgument
	}
	var ddl []string
	quote := func(name string) string { return "`" + name + "`" }
	keyNames := func(key []string) string {
		names := make([]string, len(key))
		for i, name := range key {
			names[i] = quote(name)
		}
		return strings.Join(names, ", ")
	}
	for _, t := range s.Tables {
		var cols []string
		for _, c := range t.Columns {
			typ := ""
			switch c.Type {
			case SpannerBytes:
				typ = fmt.Sprintf("BYTES(%d)", c.MaxBytes)
			case SpannerInt64:
				typ = "INT64"
			case SpannerBool:
				typ = "BOOL"
			}
			cols = append(cols, quote(c.Name)+" "+typ+" NOT NULL")
		}
		ddl = append(ddl, fmt.Sprintf("CREATE TABLE %s (\n  %s\n) PRIMARY KEY (%s)", quote(t.Name), strings.Join(cols, ",\n  "), keyNames(t.PrimaryKey)))
		for _, idx := range t.Indexes {
			unique := ""
			if idx.Unique {
				unique = "UNIQUE "
			}
			ddl = append(ddl, fmt.Sprintf("CREATE %sINDEX %s ON %s (%s)", unique, quote(idx.Name), quote(t.Name), keyNames(idx.Key)))
		}
	}
	return ddl, nil
}

// Rows counts logical insert rows; Cells and Bytes conservatively include every
// secondary-index copy and per-cell framing. Reads bounds row lookups (including
// repeated canonical parents). ReadBytes reserves at most 4 KiB per lookup:
// parent reads project publication identity/existence, never the Parents column;
// replay reads project the bounded digest/result, not canonical objects. Adapters
// must enforce that projection cap and an overall work/deadline budget.
type SpannerTransactionBudget struct{ Rows, Cells, Bytes, Reads, ReadBytes uint64 }

func spannerPublicationBudget(s SpannerSchemaDefinition) (SpannerTransactionBudget, error) {
	b := SpannerTransactionBudget{Reads: SpannerMaxPublicationReads, ReadBytes: SpannerMaxPublicationReadBytes}
	for _, name := range []string{"Publications", "EventBindings", "MutationResults", "Outbox"} {
		found := false
		for _, t := range s.Tables {
			if t.Name != name {
				continue
			}
			found = true
			b.Rows++
			// Charge full rows for each index (including implicit primary key columns),
			// deliberately overestimating both cells and bytes rather than omitting them.
			copies := uint64(1 + len(t.Indexes))
			for _, c := range t.Columns {
				n := columnSize(c)
				if n == 0 || n > SpannerMaxRowBytes || copies > SpannerMaxTransactionCells || b.Cells > SpannerMaxTransactionCells-copies {
					return b, ErrResourceExhausted
				}
				b.Cells += copies
				charge := (n + 16) * copies
				if charge > SpannerMaxTransactionBytes || b.Bytes > SpannerMaxTransactionBytes-charge {
					return b, ErrResourceExhausted
				}
				b.Bytes += charge
			}
		}
		if !found {
			return b, ErrInvalidArgument
		}
	}
	return b, nil
}

// SpannerKey owns a collision-safe physical key. Route is SHA-256 of
// B("CANOPY-METADATA-KEY-v1") || B(table) || repo[16] || B(field_0)... .
// Identity contains the framed full logical suffix, never a digest-only alias.
// Numeric identity fields use U64BE of their nonnegative logical INT64 value.
// Strings throughout are exact opaque bytes, including invalid UTF-8 and NUL.
// This is a local storage encoding, not a new canonical object or wire contract.
type SpannerKey struct {
	Route        [32]byte
	Repository   [16]byte
	Identity     string
	table, index string
}

func spannerKey(table string, repo [16]byte, fields ...string) SpannerKey {
	var frame []byte
	appendField := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		frame = append(frame, n[:]...)
		frame = append(frame, s...)
	}
	appendField("CANOPY-METADATA-KEY-v1")
	appendField(table)
	frame = append(frame, repo[:]...)
	start := len(frame)
	for _, f := range fields {
		appendField(f)
	}
	return SpannerKey{Route: sha256.Sum256(frame), Repository: repo, Identity: string(frame[start:]), table: table}
}

// SpannerKeyColumn is an owned value for one named GoogleSQL key column.
// Integer is used only for INT64; Bytes is used only for BYTES. Columns returns
// the actual separate DDL key columns, not the hash-transcript Identity string.
type SpannerKeyColumn struct {
	Name    string
	Type    SpannerType
	Bytes   []byte
	Integer int64
}

func (k SpannerKey) Columns() ([]SpannerKeyColumn, error) {
	if len(k.Identity) > int(SpannerMaxKeyBytes) {
		return nil, ErrInvalidArgument
	}
	var table *SpannerTable
	for _, t := range SpannerSchema().Tables {
		if t.Name == k.table {
			copy := t
			table = &copy
			break
		}
	}
	if table == nil {
		return nil, ErrInvalidArgument
	}
	key := table.PrimaryKey
	if k.index != "" {
		key = nil
		for _, idx := range table.Indexes {
			if idx.Name == k.index {
				key = idx.Key
				break
			}
		}
		if len(key) == 0 {
			return nil, ErrInvalidArgument
		}
	}
	fields := make([]string, 0, len(key)-2)
	remaining := k.Identity
	for len(remaining) > 0 {
		if len(remaining) < 4 {
			return nil, ErrInvalidArgument
		}
		n := uint64(binary.BigEndian.Uint32([]byte(remaining[:4])))
		remaining = remaining[4:]
		if n > uint64(len(remaining)) || len(fields) >= len(key)-2 {
			return nil, ErrInvalidArgument
		}
		fields = append(fields, remaining[:int(n)])
		remaining = remaining[int(n):]
	}
	if len(fields) != len(key)-2 || spannerKey(k.table, k.Repository, fields...).Route != k.Route {
		return nil, ErrInvalidArgument
	}
	values := []SpannerKeyColumn{{Name: key[0], Type: SpannerBytes, Bytes: append([]byte(nil), k.Route[:]...)}, {Name: key[1], Type: SpannerBytes, Bytes: append([]byte(nil), k.Repository[:]...)}}
	for i, f := range fields {
		var column SpannerColumn
		for _, c := range table.Columns {
			if c.Name == key[i+2] {
				column = c
				break
			}
		}
		v := SpannerKeyColumn{Name: column.Name, Type: column.Type}
		switch column.Type {
		case SpannerBytes:
			if len(f) == 0 || uint64(len(f)) > column.MaxBytes {
				return nil, ErrInvalidArgument
			}
			if column.Name == "Changeset" {
				if _, err := model.ParseChangesetID([]byte(f)); err != nil {
					return nil, ErrInvalidArgument
				}
			}
			if column.Name == "Operation" && (len(f) != 1 || SpannerOperation(f[0]) != SpannerPublish && SpannerOperation(f[0]) != SpannerCASRef) {
				return nil, ErrInvalidArgument
			}
			v.Bytes = []byte(f)
		case SpannerInt64:
			if len(f) != 8 {
				return nil, ErrInvalidArgument
			}
			n := binary.BigEndian.Uint64([]byte(f))
			if n > math.MaxInt64 {
				return nil, ErrInvalidArgument
			}
			if column.Name == "Version" && (n == 0 || n > math.MaxUint32) {
				return nil, ErrInvalidArgument
			}
			v.Integer = int64(n)
		default:
			return nil, ErrInvalidArgument
		}
		values = append(values, v)
	}
	return values, nil
}
func boundedSpannerString(s string, max int) error {
	if s == "" {
		return ErrInvalidArgument
	}
	if len(s) > max {
		return ErrResourceExhausted
	}
	return nil
}
func SpannerPublicationKey(repo [16]byte, id model.ChangesetID) (SpannerKey, error) {
	b, err := id.TypedID().MarshalBinary()
	if err != nil || id.Validate() != nil {
		return SpannerKey{}, ErrInvalidArgument
	}
	return spannerKey("Publications", repo, string(b)), nil
}
func SpannerPublicationIDKey(repo [16]byte, id PublicationID) (SpannerKey, error) {
	if err := boundedSpannerString(string(id), SpannerMaxOpaqueBytes); err != nil {
		return SpannerKey{}, err
	}
	key := spannerKey("Publications", repo, string(id))
	key.index = "PublicationsByID"
	return key, nil
}
func SpannerEventKey(repo [16]byte, id EventID) (SpannerKey, error) {
	if err := boundedSpannerString(string(id), SpannerMaxOpaqueBytes); err != nil {
		return SpannerKey{}, err
	}
	return spannerKey("EventBindings", repo, string(id)), nil
}
func SpannerOutboxKey(repo [16]byte, id EventID) (SpannerKey, error) {
	if err := boundedSpannerString(string(id), SpannerMaxOpaqueBytes); err != nil {
		return SpannerKey{}, err
	}
	return spannerKey("Outbox", repo, string(id)), nil
}
func SpannerOutboxShard(key SpannerKey) int64 { return int64(key.Route[0]) }

type SpannerOperation byte

const (
	SpannerPublish SpannerOperation = 1
	SpannerCASRef  SpannerOperation = 2
)

func SpannerMutationKey(repo [16]byte, principal string, op SpannerOperation, key string) (SpannerKey, error) {
	if op != SpannerPublish && op != SpannerCASRef {
		return SpannerKey{}, ErrInvalidArgument
	}
	if err := boundedSpannerString(principal, SpannerMaxPrincipalBytes); err != nil {
		return SpannerKey{}, err
	}
	if err := boundedSpannerString(key, SpannerMaxMutationBytes); err != nil {
		return SpannerKey{}, err
	}
	return spannerKey("MutationResults", repo, principal, string([]byte{byte(op)}), key), nil
}
func SpannerRefKey(repo [16]byte, name string) (SpannerKey, error) {
	if err := boundedSpannerString(name, SpannerMaxRefBytes); err != nil {
		return SpannerKey{}, err
	}
	return spannerKey("Refs", repo, name), nil
}
func SpannerDerivedKey(id DerivedIdentity) (SpannerKey, error) {
	if id.Validate() != nil {
		return SpannerKey{}, ErrInvalidArgument
	}
	if err := boundedSpannerString(id.Kind, SpannerMaxOpaqueBytes); err != nil {
		return SpannerKey{}, err
	}
	raw, _ := id.Changeset.TypedID().MarshalBinary()
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], uint64(id.Version))
	return spannerKey("DerivedMappings", id.Repository, string(raw), id.Kind, string(version[:])), nil
}

// SpannerPublicationPlan bounds the NEW-publication path. Keys reserve nothing:
// an adapter must first authenticate/authorize, resolve mutation replay, and then
// content reuse. Fresh-key content reuse returns the original event WITHOUT
// looking up or binding the proposed event. Only a new publication reads/binds
// EventBinding atomically with Publication, Mutation and Outbox. Collision is
// ErrConflict with NO effects. These are port obligations, not executed here.
//
// Durable bytes, final tree and retention are preflighted outside the transaction;
// parents are revalidated as published in this repository inside it. There is no
// ref operation, global sequence or repository-wide transaction. Deadlines,
// retry bounds, queue/retention admission, authorization/current policy, ambiguous
// commits and persistent atomicity still require the future backend. Never TTL
// EventBindings or erase them on ack. Derived parents/output need the port's
// ordered causal checks, quarantine and durable retention protocol separately.
type SpannerPublicationPlan struct {
	Publication, PublicationID, EventBinding, Mutation, Outbox SpannerKey
	Parents                                                    []SpannerKey
	Budget                                                     SpannerTransactionBudget
}

// PlanSpannerPublishRequest is the request-bound entry point for a NEW
// publication. It derives the complete ordered parent read set from the immutable
// canonical value, preventing an adapter from accidentally planning a subset.
// Content/digest, durability and final-tree verification remain external preflight.
func PlanSpannerPublishRequest(scope Scope, request PublishRequest, pub Publication) (SpannerPublicationPlan, error) {
	if request.Mutation.Validate() != nil || request.ID.Validate() != nil || request.Changeset.Validate() != nil || request.ID != pub.Changeset || request.Event != pub.Event {
		return SpannerPublicationPlan{}, ErrInvalidArgument
	}
	// Validate all admission fields before cloning potentially large canonical data.
	if _, err := PlanSpannerPublication(scope, request.Mutation, pub, nil, request.Changeset.PayloadSize()); err != nil {
		return SpannerPublicationPlan{}, err
	}
	input := request.Changeset.Snapshot()
	if input.RepoID != scope.Repository {
		return SpannerPublicationPlan{}, ErrInvalidArgument
	}
	return PlanSpannerPublication(scope, request.Mutation, pub, input.Parents, request.Changeset.PayloadSize())
}

// PlanSpannerPublication is the bounded metadata-only shape helper. Its parent
// slice and payload count are caller assertions, not canonical validation. Use
// PlanSpannerPublishRequest to derive them from a verified immutable request.
func PlanSpannerPublication(scope Scope, mutation Mutation, pub Publication, parents []model.ChangesetID, payloadBytes uint64) (SpannerPublicationPlan, error) {
	fail := func(err error) (SpannerPublicationPlan, error) { return SpannerPublicationPlan{}, err }
	if pub.Repository != scope.Repository || mutation.Validate() != nil || pub.Changeset.Validate() != nil {
		return fail(ErrInvalidArgument)
	}
	if payloadBytes > model.MaxChangesetPayload || uint64(len(parents)) > model.MaxParents {
		return fail(ErrResourceExhausted)
	}
	var p SpannerPublicationPlan
	var err error
	if p.Publication, err = SpannerPublicationKey(pub.Repository, pub.Changeset); err != nil {
		return fail(err)
	}
	if p.PublicationID, err = SpannerPublicationIDKey(pub.Repository, pub.ID); err != nil {
		return fail(err)
	}
	if p.EventBinding, err = SpannerEventKey(pub.Repository, pub.Event); err != nil {
		return fail(err)
	}
	if p.Mutation, err = SpannerMutationKey(pub.Repository, scope.Principal, SpannerPublish, mutation.Key); err != nil {
		return fail(err)
	}
	if p.Outbox, err = SpannerOutboxKey(pub.Repository, pub.Event); err != nil {
		return fail(err)
	}
	for _, id := range parents {
		if id.Validate() != nil {
			return fail(ErrInvalidArgument)
		}
	}
	// Allocation follows all count, byte and typed-ID admission checks.
	p.Parents = make([]SpannerKey, len(parents))
	for i, id := range parents {
		p.Parents[i], _ = SpannerPublicationKey(pub.Repository, id)
	}
	p.Budget, err = spannerPublicationBudget(SpannerSchema())
	if err != nil {
		return fail(err)
	}
	p.Budget.Reads = uint64(len(parents)) + 3
	p.Budget.ReadBytes = p.Budget.Reads * SpannerMaxReadRowBytes
	return p, nil
}

// EncodeSpannerDerivedParents preserves full repository, typed identities,
// ordered causal inputs and exact output IDs. It validates every bound before
// allocating; a derived value is never a canonical changeset/tree-kind TID.
func EncodeSpannerDerivedParents(w DerivedWrite) ([]byte, error) {
	if w.Validate() != nil {
		return nil, ErrInvalidArgument
	}
	if _, err := SpannerDerivedKey(w.Result.Identity); err != nil {
		return nil, err
	}
	size := 4
	for _, p := range w.Parents {
		if _, err := SpannerDerivedKey(p.Identity); err != nil {
			return nil, err
		}
		size += 16 + 35 + 4 + len(p.Identity.Kind) + 4 + 39
	}
	out := make([]byte, 4, size)
	binary.BigEndian.PutUint32(out, uint32(len(w.Parents)))
	for _, p := range w.Parents {
		out = append(out, p.Identity.Repository[:]...)
		id, _ := p.Identity.Changeset.TypedID().MarshalBinary()
		out = append(out, id...)
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p.Identity.Kind)))
		out = append(out, n[:]...)
		out = append(out, p.Identity.Kind...)
		binary.BigEndian.PutUint32(n[:], p.Identity.Version)
		out = append(out, n[:]...)
		out = append(out, p.Value.Bytes()...)
	}
	return out, nil
}
