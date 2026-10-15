package metadata_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

func hasSpannerIssue(issues []metadata.SpannerSchemaIssue, table, key, reason string) bool {
	for _, issue := range issues {
		if issue.Table == table && issue.Key == key && issue.Reason == reason {
			return true
		}
	}
	return false
}

func requireSpannerIssue(t *testing.T, issues []metadata.SpannerSchemaIssue, table, key, reason string) {
	t.Helper()
	if !hasSpannerIssue(issues, table, key, reason) {
		t.Fatalf("ReviewSpannerSchema(%s, %s) issues = %+v, want reason %q", table, key, issues, reason)
	}
}

func schemaTable(t *testing.T, schema *metadata.SpannerSchemaDefinition, name string) *metadata.SpannerTable {
	t.Helper()
	for i := range schema.Tables {
		if schema.Tables[i].Name == name {
			return &schema.Tables[i]
		}
	}
	t.Fatalf("schema has no table %q", name)
	return nil
}

func schemaColumn(t *testing.T, table *metadata.SpannerTable, name string) *metadata.SpannerColumn {
	t.Helper()
	for i := range table.Columns {
		if table.Columns[i].Name == name {
			return &table.Columns[i]
		}
	}
	t.Fatalf("table %q has no column %q", table.Name, name)
	return nil
}

func schemaFrameField(dst, field []byte) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(field)))
	dst = append(dst, size[:]...)
	return append(dst, field...)
}

func schemaRouteForTest(table string, repo [16]byte, fields ...[]byte) [32]byte {
	frame := schemaFrameField(nil, []byte("CANOPY-METADATA-KEY-v1"))
	frame = schemaFrameField(frame, []byte(table))
	frame = append(frame, repo[:]...)
	for _, field := range fields {
		frame = schemaFrameField(frame, field)
	}
	return sha256.Sum256(frame)
}

func TestSpannerSchemaIsFreshBoundedAndEmitsDDL(t *testing.T) {
	schema := metadata.SpannerSchema()
	if issues := metadata.ReviewSpannerSchema(schema); len(issues) != 0 {
		t.Fatalf("fresh schema rejected: %+v", issues)
	}
	ddl, err := metadata.SpannerDDL(schema)
	if err != nil {
		t.Fatalf("fresh schema DDL: %v", err)
	}
	if len(ddl) != 8 { // six tables and two declared secondary indexes
		t.Fatalf("DDL statement count = %d, want 8: %v", len(ddl), ddl)
	}
	joined := strings.Join(ddl, "\n")
	for _, fragment := range []string{
		"CREATE TABLE `Publications`",
		"PRIMARY KEY (`Route`, `Repository`, `Changeset`)",
		"CREATE UNIQUE INDEX `PublicationsByID` ON `Publications`",
		"CREATE INDEX `OutboxPending` ON `Outbox`",
		"`Parents` BYTES(35844) NOT NULL",
		"`PayloadBytes` INT64 NOT NULL",
		"`Acknowledged` BOOL NOT NULL",
	} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("DDL missing %q:\n%s", fragment, joined)
		}
	}
	if strings.Contains(joined, "BYTES(MAX)") {
		t.Fatalf("DDL contains an unbounded BYTES type:\n%s", joined)
	}

	// Returned descriptors own their table, column, key, and index slices.
	schema.Tables[0].Name = "Changed"
	schema.Tables[0].Columns[0].Name = "Changed"
	schema.Tables[0].PrimaryKey[0] = "Changed"
	schema.Tables[0].Indexes[0].Key[0] = "Changed"
	fresh := metadata.SpannerSchema()
	if fresh.Tables[0].Name != "Publications" || fresh.Tables[0].Columns[0].Name != "Route" ||
		fresh.Tables[0].PrimaryKey[0] != "Route" || fresh.Tables[0].Indexes[0].Key[0] != "PublicationRoute" {
		t.Fatalf("SpannerSchema returned shared mutable state: %+v", fresh.Tables[0])
	}
}

func TestReviewSpannerSchemaChecksSemanticKeyDistribution(t *testing.T) {
	t.Run("renamed sequential primary key", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		outbox := schemaTable(t, &schema, "Outbox")
		outbox.Columns = append(outbox.Columns, metadata.SpannerColumn{
			Name: "CreatedAt", Type: metadata.SpannerInt64, Semantic: metadata.SpannerSequential,
		})
		outbox.PrimaryKey = append([]string{"CreatedAt"}, outbox.PrimaryKey...)
		issues := metadata.ReviewSpannerSchema(schema)
		requireSpannerIssue(t, issues, "Outbox", "PRIMARY KEY", "leading key is not distributed")
		if ddl, err := metadata.SpannerDDL(schema); err == nil || ddl != nil {
			t.Fatalf("DDL accepted a sequential leading key: ddl=%v err=%v", ddl, err)
		}
	})

	t.Run("renamed sequential secondary index key", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		outbox := schemaTable(t, &schema, "Outbox")
		outbox.Columns = append(outbox.Columns, metadata.SpannerColumn{
			Name: "LastUpdated", Type: metadata.SpannerInt64, Semantic: metadata.SpannerSequential,
		})
		outbox.Indexes[0].Key = append([]string{"LastUpdated"}, outbox.Indexes[0].Key...)
		issues := metadata.ReviewSpannerSchema(schema)
		requireSpannerIssue(t, issues, "Outbox", "OutboxPending", "leading key is not distributed")
	})

	t.Run("hash and shard in second position do not distribute the lead", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		outbox := schemaTable(t, &schema, "Outbox")
		outbox.PrimaryKey = []string{"Repository", "Route", "Event"}
		outbox.Indexes[0].Key = []string{"Repository", "Shard", "Acknowledged", "Route", "Event"}
		issues := metadata.ReviewSpannerSchema(schema)
		requireSpannerIssue(t, issues, "Outbox", "PRIMARY KEY", "leading key is not distributed")
		requireSpannerIssue(t, issues, "Outbox", "OutboxPending", "leading key is not distributed")
	})

	t.Run("repository only hash has no varying identity", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		outbox := schemaTable(t, &schema, "Outbox")
		schemaColumn(t, outbox, "Route").HashOf = []string{"Repository"}
		requireSpannerIssue(t, metadata.ReviewSpannerSchema(schema), "Outbox", "Route", "hash must include repository and varying identity")
	})
}

func TestReviewSpannerSchemaChecksStorageAndKeyBounds(t *testing.T) {
	for _, tc := range []struct {
		name, table, column, key, reason string
		bound                            uint64
		semantic                         metadata.SpannerSemantic
	}{
		{"zero bound", "Publications", "Parents", "Parents", "unbounded or oversized row/type", 0, metadata.SpannerValue},
		{"single type larger than row limit", "Publications", "Parents", "Parents", "unbounded or oversized row/type", metadata.SpannerMaxRowBytes + 1, metadata.SpannerValue},
		{"canonical payload cannot be stored in metadata row", "Publications", "Parents", "Parents", "canonical payload belongs in object storage", 35844, metadata.SpannerCanonicalPayload},
		{"key byte limit", "Refs", "Name", "PRIMARY KEY", "oversized key", metadata.SpannerMaxKeyBytes, metadata.SpannerIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			schema := metadata.SpannerSchema()
			column := schemaColumn(t, schemaTable(t, &schema, tc.table), tc.column)
			column.MaxBytes, column.Semantic = tc.bound, tc.semantic
			requireSpannerIssue(t, metadata.ReviewSpannerSchema(schema), tc.table, tc.key, tc.reason)
		})
	}
	t.Run("aggregate row exceeds row limit", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		refs := schemaTable(t, &schema, "Refs")
		schemaColumn(t, refs, "Name").MaxBytes = 140 << 10
		schemaColumn(t, refs, "Target").MaxBytes = 140 << 10
		requireSpannerIssue(t, metadata.ReviewSpannerSchema(schema), "Refs", "Target", "unbounded or oversized row/type")
	})
}

func TestReviewSpannerSchemaChecksIndexAmplificationAndStructure(t *testing.T) {
	t.Run("index amplification exceeds transaction cells", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		pubs := schemaTable(t, &schema, "Publications")
		for i := 0; i < 126; i++ {
			pubs.Indexes = append(pubs.Indexes, metadata.SpannerIndex{
				Name: "PublicationExtra" + strings.Repeat("x", i%3) + string(rune('A'+i%26)) + string(rune('a'+i/26)),
				Key:  []string{"PublicationRoute", "Repository", "Publication"},
			})
		}
		requireSpannerIssue(t, metadata.ReviewSpannerSchema(schema), "Publications", "transaction", "publication mutation budget exceeded or missing table")
	})

	t.Run("missing indexed identity field", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		outbox := schemaTable(t, &schema, "Outbox")
		columns := outbox.Columns[:0]
		for _, column := range outbox.Columns {
			if column.Name != "Event" {
				columns = append(columns, column)
			}
		}
		outbox.Columns = columns
		issues := metadata.ReviewSpannerSchema(schema)
		if !hasSpannerIssue(issues, "Outbox", "PRIMARY KEY", "missing or duplicate key column") &&
			!hasSpannerIssue(issues, "Outbox", "Route", "invalid hash input") {
			t.Fatalf("missing key/hash input was not reported: %+v", issues)
		}
	})

	t.Run("duplicate columns and tables", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		outbox := schemaTable(t, &schema, "Outbox")
		outbox.Columns = append(outbox.Columns, outbox.Columns[0])
		schema.Tables = append(schema.Tables, schema.Tables[0])
		issues := metadata.ReviewSpannerSchema(schema)
		if !hasSpannerIssue(issues, "Outbox", "Route", "duplicate column") {
			t.Fatalf("duplicate column was not reported: %+v", issues)
		}
		if !hasSpannerIssue(issues, "Publications", "", "invalid or duplicate table") {
			t.Fatalf("duplicate table was not reported: %+v", issues)
		}
	})

	t.Run("required metadata tables", func(t *testing.T) {
		for _, missing := range []string{"Refs", "DerivedMappings"} {
			t.Run(missing, func(t *testing.T) {
				schema := metadata.SpannerSchema()
				kept := schema.Tables[:0]
				for _, table := range schema.Tables {
					if table.Name != missing {
						kept = append(kept, table)
					}
				}
				schema.Tables = kept
				requireSpannerIssue(t, metadata.ReviewSpannerSchema(schema), missing, "", "missing required metadata table")
			})
		}
	})
}

func TestSpannerSchemaRepairRegressions(t *testing.T) {
	check := func(t *testing.T, schema metadata.SpannerSchemaDefinition, table, key, reason string) {
		t.Helper()
		issues := metadata.ReviewSpannerSchema(schema)
		ddl, err := metadata.SpannerDDL(schema)
		if reason == "" {
			if len(issues) != 0 || err != nil || len(ddl) == 0 {
				t.Fatalf("safe schema rejected: issues=%+v ddl=%v err=%v", issues, ddl, err)
			}
		} else {
			requireSpannerIssue(t, issues, table, key, reason)
			if err != metadata.ErrInvalidArgument || ddl != nil {
				t.Fatalf("invalid schema emitted DDL: ddl=%v err=%v", ddl, err)
			}
		}
	}
	for _, fields := range [][]string{
		{"Repository", "Operation"}, // CORE-01: the independent two-valued hash counterexample.
		{"Repository", "Operation", "Principal"},
		{"Repository", "Operation", "Mutation"},
		{"Repository", "Operation", "Principal", "Mutation"},
	} {
		t.Run("secondary identity/"+strings.Join(fields, "+"), func(t *testing.T) {
			schema := metadata.SpannerSchema()
			row := schemaTable(t, &schema, "MutationResults")
			row.Columns = append(row.Columns, metadata.SpannerColumn{Name: "ActionRoute", Type: metadata.SpannerBytes, MaxBytes: 32, Semantic: metadata.SpannerHash, HashOf: fields})
			row.Indexes = append(row.Indexes, metadata.SpannerIndex{Name: "MutationActions", Key: []string{"ActionRoute", "Repository", "Operation", "Principal", "Mutation"}})
			reason := "routing hash omits logical key field"
			if len(fields) == 4 {
				reason = ""
				row.Columns = append(row.Columns, metadata.SpannerColumn{Name: "Filter", Type: metadata.SpannerBool, Semantic: metadata.SpannerValue})
				row.Indexes[0].Key = append(row.Indexes[0].Key, "Filter")
			}
			check(t, schema, row.Name, "MutationActions", reason)
		})
	}
	// CORE-02: the implicit Route + Changeset cost 99 framed bytes. The
	// independent 3856-byte tag charges 4096 explicitly, but 4195 physically.
	for _, bound := range []uint64{3757, 3758, 3856, ^uint64(0)} {
		for _, explicitPK := range []bool{false, true} {
			t.Run(fmt.Sprintf("physical key/%d/explicitPK=%t", bound, explicitPK), func(t *testing.T) {
				schema := metadata.SpannerSchema()
				row := schemaTable(t, &schema, "Publications")
				row.Columns = append(row.Columns, metadata.SpannerColumn{Name: "LookupTag", Type: metadata.SpannerBytes, MaxBytes: bound, Semantic: metadata.SpannerValue})
				// Preserve the physical-size witness without weakening the required
				// publication-ID uniqueness by extending its mandatory key.
				row.Indexes = append(row.Indexes, metadata.SpannerIndex{Name: "PublicationTag", Key: []string{"PublicationRoute", "Repository", "Publication", "LookupTag"}, Unique: true})
				if explicitPK {
					row.Indexes[1].Key = append(row.Indexes[1].Key, "Route")
				}
				reason := "oversized key"
				if bound == 3757 {
					reason = ""
				}
				check(t, schema, row.Name, "PublicationTag", reason)
			})
		}
	}
	// CORE-03: independently remove every baseline column, including all five
	// reported non-key fields; also reject incompatible widths/types/semantics.
	for _, table := range metadata.SpannerSchema().Tables {
		for _, column := range table.Columns {
			for _, change := range []string{"delete", "type", "width", "semantic", "hash inputs"} {
				t.Run(table.Name+"/"+column.Name+"/"+change, func(t *testing.T) {
					schema := metadata.SpannerSchema()
					row := schemaTable(t, &schema, table.Name)
					c := schemaColumn(t, row, column.Name)
					switch change {
					case "delete":
						for i := range row.Columns {
							if row.Columns[i].Name == column.Name {
								row.Columns = append(row.Columns[:i], row.Columns[i+1:]...)
								break
							}
						}
					case "type":
						c.Type = metadata.SpannerType(int(c.Type)%3 + 1)
					case "width":
						c.MaxBytes++
					case "semantic":
						c.Semantic = metadata.SpannerSemantic(int(c.Semantic)%7 + 1)
					case "hash inputs":
						c.HashOf = append(c.HashOf, "Repository")
					}
					check(t, schema, table.Name, column.Name, "missing or incompatible required column")
				})
			}
		}
	}
}

func TestSpannerKeysHaveIndependentGoldenAndUnambiguousFrames(t *testing.T) {
	repo := repoA()
	id := changesetA(t)
	key, err := metadata.SpannerPublicationKey(repo, id)
	if err != nil {
		t.Fatal(err)
	}
	typed, err := id.TypedID().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	frame := schemaFrameField(nil, []byte("CANOPY-METADATA-KEY-v1"))
	frame = schemaFrameField(frame, []byte("Publications"))
	frame = append(frame, repo[:]...)
	frame = schemaFrameField(frame, typed)
	wantIdentity := schemaFrameField(nil, typed)
	wantRoute := sha256.Sum256(frame)
	if key.Route != wantRoute || key.Identity != string(wantIdentity) {
		t.Fatalf("publication frame mismatch: route=%x identity=%x", key.Route, []byte(key.Identity))
	}
	if got := hex.EncodeToString(key.Route[:]); got != "126b901a4cfc620752ae60b63327b2183bd387a58743526a63118c8871fa2c80" {
		t.Fatalf("publication route golden = %s", got)
	}

	raw := string([]byte{0xff, 0x00, 0xfe})
	opaque, err := metadata.SpannerEventKey(repo, metadata.EventID(raw))
	if err != nil {
		t.Fatal(err)
	}
	if want := string(schemaFrameField(nil, []byte(raw))); opaque.Identity != want {
		t.Fatalf("event frame did not preserve NUL/non-UTF8 bytes: got %x want %x", []byte(opaque.Identity), []byte(want))
	}
	if _, err := metadata.SpannerEventKey(repo, metadata.EventID("")); err != metadata.ErrInvalidArgument {
		t.Fatalf("empty event ID error = %v, want ErrInvalidArgument", err)
	}

	// Without field lengths these distinct tuples flatten to the same bytes.
	left, err := metadata.SpannerMutationKey(repo, "a\x01", metadata.SpannerPublish, "b")
	if err != nil {
		t.Fatal(err)
	}
	right, err := metadata.SpannerMutationKey(repo, "a", metadata.SpannerPublish, "\x01b")
	if err != nil {
		t.Fatal(err)
	}
	if left.Route == right.Route || left.Identity == right.Identity {
		t.Fatalf("ambiguous mutation tuples aliased: left=%+v right=%+v", left, right)
	}
}

func TestSpannerKeyRoutingSeparatesScopeOperationKindAndVersion(t *testing.T) {
	repo := repoA()
	otherRepo := [16]byte{2}
	eventA, err := metadata.SpannerEventKey(repo, "same-event")
	if err != nil {
		t.Fatal(err)
	}
	eventB, err := metadata.SpannerEventKey(otherRepo, "same-event")
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := metadata.SpannerOutboxKey(repo, "same-event")
	if err != nil {
		t.Fatal(err)
	}
	if eventA.Route == eventB.Route || eventA.Route == outbox.Route {
		t.Fatal("repository or table domain is absent from routed key")
	}

	publish, err := metadata.SpannerMutationKey(repo, "principal", metadata.SpannerPublish, "mutation")
	if err != nil {
		t.Fatal(err)
	}
	refCAS, err := metadata.SpannerMutationKey(repo, "principal", metadata.SpannerCASRef, "mutation")
	if err != nil {
		t.Fatal(err)
	}
	if publish.Route == refCAS.Route {
		t.Fatal("operation kind is absent from mutation key")
	}

	base := metadata.DerivedIdentity{Repository: repo, Changeset: changesetA(t), Kind: "tree-index", Version: 0x01020304}
	baseKey, err := metadata.SpannerDerivedKey(base)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(baseKey.Route[:]); got != "fb6e6b93749e69f998171bcfd48b6a6f3a2106c67f065cd1c3737575025f39af" {
		t.Fatalf("derived version key golden = %s", got)
	}
	variants := []metadata.DerivedIdentity{
		{Repository: otherRepo, Changeset: base.Changeset, Kind: base.Kind, Version: base.Version},
		{Repository: repo, Changeset: changesetB(t), Kind: base.Kind, Version: base.Version},
		{Repository: repo, Changeset: base.Changeset, Kind: "other-kind", Version: base.Version},
		{Repository: repo, Changeset: base.Changeset, Kind: base.Kind, Version: base.Version + 1},
	}
	for i, identity := range variants {
		got, err := metadata.SpannerDerivedKey(identity)
		if err != nil {
			t.Fatalf("variant %d key: %v", i, err)
		}
		if got.Route == baseKey.Route || (got.Repository == baseKey.Repository && got.Identity == baseKey.Identity) {
			t.Fatalf("derived scope variant %d aliases base key", i)
		}
	}
}

func TestSpannerOutboxHashDistributesSequentialEventIDs(t *testing.T) {
	seenShards := make(map[int64]struct{})
	var previous byte
	descending := false
	for i := 0; i < 256; i++ {
		event := metadata.EventID(fmt.Sprintf("event-%06d", i))
		key, err := metadata.SpannerOutboxKey(repoA(), event)
		if err != nil {
			t.Fatalf("event %d key: %v", i, err)
		}
		shard := metadata.SpannerOutboxShard(key)
		seenShards[shard] = struct{}{}
		if i > 0 && key.Route[0] < previous {
			descending = true
		}
		previous = key.Route[0]
	}
	if len(seenShards) < 100 || !descending {
		t.Fatalf("sequential event IDs clustered: %d first-byte shards, descending=%v", len(seenShards), descending)
	}
}

func TestSpannerKeyBoundsAndInvalidTypes(t *testing.T) {
	repo := repoA()
	if _, err := metadata.SpannerPublicationIDKey(repo, metadata.PublicationID(strings.Repeat("p", metadata.SpannerMaxOpaqueBytes))); err != nil {
		t.Fatalf("maximum publication ID rejected: %v", err)
	}
	if _, err := metadata.SpannerPublicationIDKey(repo, metadata.PublicationID(strings.Repeat("p", metadata.SpannerMaxOpaqueBytes+1))); err != metadata.ErrResourceExhausted {
		t.Fatalf("overlong publication ID error = %v", err)
	}
	if _, err := metadata.SpannerEventKey(repo, metadata.EventID(strings.Repeat("e", metadata.SpannerMaxOpaqueBytes+1))); err != metadata.ErrResourceExhausted {
		t.Fatalf("overlong event ID error = %v", err)
	}
	if _, err := metadata.SpannerMutationKey(repo, strings.Repeat("u", metadata.SpannerMaxPrincipalBytes), metadata.SpannerPublish, strings.Repeat("m", metadata.SpannerMaxMutationBytes)); err != nil {
		t.Fatalf("maximum mutation principal/key rejected: %v", err)
	}
	if _, err := metadata.SpannerMutationKey(repo, strings.Repeat("u", metadata.SpannerMaxPrincipalBytes+1), metadata.SpannerPublish, "m"); err != metadata.ErrResourceExhausted {
		t.Fatalf("overlong principal error = %v", err)
	}
	if _, err := metadata.SpannerMutationKey(repo, "u", metadata.SpannerPublish, strings.Repeat("m", metadata.SpannerMaxMutationBytes+1)); err != metadata.ErrResourceExhausted {
		t.Fatalf("overlong mutation key error = %v", err)
	}
	if _, err := metadata.SpannerMutationKey(repo, "u", metadata.SpannerOperation(0), "m"); err != metadata.ErrInvalidArgument {
		t.Fatalf("unknown mutation operation error = %v", err)
	}
	if _, err := metadata.SpannerRefKey(repo, strings.Repeat("r", metadata.SpannerMaxRefBytes)); err != nil {
		t.Fatalf("maximum ref name rejected: %v", err)
	}
	if _, err := metadata.SpannerRefKey(repo, strings.Repeat("r", metadata.SpannerMaxRefBytes+1)); err != metadata.ErrResourceExhausted {
		t.Fatalf("overlong ref name error = %v", err)
	}
	if _, err := metadata.SpannerPublicationKey(repo, model.ChangesetID{}); err != metadata.ErrInvalidArgument {
		t.Fatalf("zero changeset ID error = %v", err)
	}
	if _, err := metadata.SpannerDerivedKey(metadata.DerivedIdentity{Repository: repo, Changeset: changesetA(t), Kind: "x", Version: 0}); err != metadata.ErrInvalidArgument {
		t.Fatalf("zero derived version error = %v", err)
	}
	if _, err := metadata.SpannerDerivedKey(metadata.DerivedIdentity{Repository: repo, Changeset: changesetA(t), Kind: strings.Repeat("k", metadata.SpannerMaxOpaqueBytes+1), Version: 1}); err != metadata.ErrResourceExhausted {
		t.Fatalf("overlong derived kind error = %v", err)
	}
}

func TestSpannerKeyColumnsMatchSchemaAndOwnTheirBytes(t *testing.T) {
	repo := repoA()
	changeset := changesetA(t)
	typed, err := changeset.TypedID().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	derived := metadata.DerivedIdentity{Repository: repo, Changeset: changeset, Kind: "tree-index", Version: 9}
	publicationKey, err := metadata.SpannerPublicationKey(repo, changeset)
	if err != nil {
		t.Fatal(err)
	}
	publicationIDKey, err := metadata.SpannerPublicationIDKey(repo, "publication")
	if err != nil {
		t.Fatal(err)
	}
	eventKey, err := metadata.SpannerEventKey(repo, "event")
	if err != nil {
		t.Fatal(err)
	}
	outboxKey, err := metadata.SpannerOutboxKey(repo, "event")
	if err != nil {
		t.Fatal(err)
	}
	mutationKey, err := metadata.SpannerMutationKey(repo, "principal", metadata.SpannerPublish, "mutation")
	if err != nil {
		t.Fatal(err)
	}
	refKey, err := metadata.SpannerRefKey(repo, "refs/main")
	if err != nil {
		t.Fatal(err)
	}
	derivedKey, err := metadata.SpannerDerivedKey(derived)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		key  metadata.SpannerKey
		want []metadata.SpannerKeyColumn
	}{
		{
			name: "publication primary key",
			key:  publicationKey,
			want: []metadata.SpannerKeyColumn{
				{Name: "Route", Type: metadata.SpannerBytes}, {Name: "Repository", Type: metadata.SpannerBytes}, {Name: "Changeset", Type: metadata.SpannerBytes, Bytes: typed},
			},
		},
		{
			name: "publication ID index",
			key:  publicationIDKey,
			want: []metadata.SpannerKeyColumn{
				{Name: "PublicationRoute", Type: metadata.SpannerBytes}, {Name: "Repository", Type: metadata.SpannerBytes}, {Name: "Publication", Type: metadata.SpannerBytes, Bytes: []byte("publication")},
			},
		},
		{
			name: "event binding primary key",
			key:  eventKey,
			want: []metadata.SpannerKeyColumn{
				{Name: "Route", Type: metadata.SpannerBytes}, {Name: "Repository", Type: metadata.SpannerBytes}, {Name: "Event", Type: metadata.SpannerBytes, Bytes: []byte("event")},
			},
		},
		{
			name: "outbox primary key",
			key:  outboxKey,
			want: []metadata.SpannerKeyColumn{
				{Name: "Route", Type: metadata.SpannerBytes}, {Name: "Repository", Type: metadata.SpannerBytes}, {Name: "Event", Type: metadata.SpannerBytes, Bytes: []byte("event")},
			},
		},
		{
			name: "mutation result primary key",
			key:  mutationKey,
			want: []metadata.SpannerKeyColumn{
				{Name: "Route", Type: metadata.SpannerBytes}, {Name: "Repository", Type: metadata.SpannerBytes}, {Name: "Principal", Type: metadata.SpannerBytes, Bytes: []byte("principal")},
				{Name: "Operation", Type: metadata.SpannerBytes, Bytes: []byte{byte(metadata.SpannerPublish)}}, {Name: "Mutation", Type: metadata.SpannerBytes, Bytes: []byte("mutation")},
			},
		},
		{
			name: "ref primary key",
			key:  refKey,
			want: []metadata.SpannerKeyColumn{
				{Name: "Route", Type: metadata.SpannerBytes}, {Name: "Repository", Type: metadata.SpannerBytes}, {Name: "Name", Type: metadata.SpannerBytes, Bytes: []byte("refs/main")},
			},
		},
		{
			name: "derived mapping primary key",
			key:  derivedKey,
			want: []metadata.SpannerKeyColumn{
				{Name: "Route", Type: metadata.SpannerBytes}, {Name: "Repository", Type: metadata.SpannerBytes}, {Name: "Changeset", Type: metadata.SpannerBytes, Bytes: typed},
				{Name: "Kind", Type: metadata.SpannerBytes, Bytes: []byte("tree-index")}, {Name: "Version", Type: metadata.SpannerInt64, Integer: 9},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.key.Columns()
			if err != nil {
				t.Fatalf("Columns: %v", err)
			}
			want := append([]metadata.SpannerKeyColumn(nil), test.want...)
			want[0].Bytes = append([]byte(nil), test.key.Route[:]...)
			want[1].Bytes = append([]byte(nil), repo[:]...)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("SQL key columns = %+v, want %+v", got, want)
			}
			for i := range got {
				if len(got[i].Bytes) != 0 {
					got[i].Bytes[0] ^= 0xff
				}
			}
			again, err := test.key.Columns()
			if err != nil || !reflect.DeepEqual(again, want) {
				t.Fatalf("Columns result aliases caller bytes: err=%v got=%+v want=%+v", err, again, want)
			}
		})
	}

	key, err := metadata.SpannerMutationKey(repo, "principal", metadata.SpannerPublish, "mutation")
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []struct {
		name string
		edit func(*metadata.SpannerKey)
	}{
		{name: "truncated identity", edit: func(k *metadata.SpannerKey) { k.Identity = k.Identity[:len(k.Identity)-1] }},
		{name: "modified identity", edit: func(k *metadata.SpannerKey) {
			k.Identity = k.Identity[:len(k.Identity)-1] + string([]byte{k.Identity[len(k.Identity)-1] ^ 1})
		}},
		{name: "modified route", edit: func(k *metadata.SpannerKey) { k.Route[0] ^= 1 }},
		{name: "modified repository", edit: func(k *metadata.SpannerKey) { k.Repository[0] ^= 1 }},
		{name: "oversized identity", edit: func(k *metadata.SpannerKey) { k.Identity = strings.Repeat("x", int(metadata.SpannerMaxKeyBytes)+1) }},
	} {
		t.Run("reject "+mutate.name, func(t *testing.T) {
			bad := key
			mutate.edit(&bad)
			if got, err := bad.Columns(); err == nil || got != nil {
				t.Fatalf("Columns accepted corrupted key: columns=%+v err=%v", got, err)
			}
		})
	}

	t.Run("reject invalid typed changeset key value", func(t *testing.T) {
		badID := append([]byte(nil), typed...)
		badID[2] = 0xff
		bad := publicationKey
		bad.Identity = string(schemaFrameField(nil, badID))
		bad.Route = schemaRouteForTest("Publications", repo, badID)
		if got, err := bad.Columns(); err == nil || got != nil {
			t.Fatalf("Columns accepted invalid typed changeset: columns=%+v err=%v", got, err)
		}
	})

	t.Run("reject unknown mutation operation value", func(t *testing.T) {
		bad := mutationKey
		fields := [][]byte{[]byte("principal"), {0xff}, []byte("mutation")}
		bad.Identity = ""
		for _, field := range fields {
			bad.Identity = string(schemaFrameField([]byte(bad.Identity), field))
		}
		bad.Route = schemaRouteForTest("MutationResults", repo, fields...)
		if got, err := bad.Columns(); err == nil || got != nil {
			t.Fatalf("Columns accepted unknown mutation operation: columns=%+v err=%v", got, err)
		}
	})

	t.Run("reject zero or out of range derived version", func(t *testing.T) {
		for _, version := range []uint64{0, uint64(1) << 32} {
			bad := derivedKey
			var encoded [8]byte
			binary.BigEndian.PutUint64(encoded[:], version)
			fields := [][]byte{typed, []byte("tree-index"), encoded[:]}
			bad.Identity = ""
			for _, field := range fields {
				bad.Identity = string(schemaFrameField([]byte(bad.Identity), field))
			}
			bad.Route = schemaRouteForTest("DerivedMappings", repo, fields...)
			if got, err := bad.Columns(); err == nil || got != nil {
				t.Fatalf("Columns accepted derived version %d: columns=%+v err=%v", version, got, err)
			}
		}
	})
}

func TestPlanSpannerPublicationBoundsZeroOnErrorAndOwnsParents(t *testing.T) {
	repo := repoA()
	scope := metadata.Scope{Repository: repo, Principal: "principal"}
	mutation := metadata.Mutation{Key: "mutation-1", RequestDigest: [32]byte{7}}
	publication := metadata.Publication{Repository: repo, Changeset: changesetA(t), ID: "publication-1", Event: "event-1"}
	parents := make([]model.ChangesetID, int(model.MaxParents))
	for i := range parents {
		parents[i] = changesetA(t)
	}
	plan, err := metadata.PlanSpannerPublication(scope, mutation, publication, parents, model.MaxChangesetPayload)
	if err != nil {
		t.Fatalf("maximum valid publication plan rejected: %v", err)
	}
	if len(plan.Parents) != int(model.MaxParents) || plan.Budget.Rows != metadata.SpannerMaxPublicationRows ||
		plan.Budget.Cells > metadata.SpannerMaxTransactionCells || plan.Budget.Bytes > metadata.SpannerMaxTransactionBytes ||
		plan.Budget.Reads != metadata.SpannerMaxPublicationReads || plan.Budget.ReadBytes != metadata.SpannerMaxPublicationReadBytes ||
		plan.Budget.ReadBytes != plan.Budget.Reads*metadata.SpannerMaxReadRowBytes {
		t.Fatalf("plan exceeded or failed to report declared bounds: parents=%d budget=%+v", len(plan.Parents), plan.Budget)
	}
	wantFirst, err := metadata.SpannerPublicationKey(repo, changesetA(t))
	if err != nil || plan.Parents[0] != wantFirst {
		t.Fatalf("first planned parent = %+v, want %+v (err %v)", plan.Parents[0], wantFirst, err)
	}
	parents[0] = changesetB(t)
	if plan.Parents[0] != wantFirst {
		t.Fatal("plan parent keys alias the caller's parent slice")
	}
	plan.Parents[0] = metadata.SpannerKey{}
	if parents[0] != changesetB(t) {
		t.Fatal("returned parent-key slice aliases the caller's parent slice")
	}

	for _, test := range []struct {
		name        string
		parents     []model.ChangesetID
		payload     uint64
		publication metadata.Publication
		mutation    metadata.Mutation
		want        error
	}{
		{name: "too many parents", parents: make([]model.ChangesetID, int(model.MaxParents+1)), payload: 0, publication: publication, mutation: mutation, want: metadata.ErrResourceExhausted},
		{name: "payload one over maximum", parents: nil, payload: model.MaxChangesetPayload + 1, publication: publication, mutation: mutation, want: metadata.ErrResourceExhausted},
		{name: "scope mismatch", parents: nil, payload: 0, publication: metadata.Publication{Repository: [16]byte{2}, Changeset: changesetA(t), ID: "p", Event: "e"}, mutation: mutation, want: metadata.ErrInvalidArgument},
		{name: "invalid parent typed ID", parents: []model.ChangesetID{{}}, payload: 0, publication: publication, mutation: mutation, want: metadata.ErrInvalidArgument},
		{name: "oversized event identity", parents: nil, payload: 0, publication: metadata.Publication{Repository: repo, Changeset: changesetA(t), ID: "p", Event: metadata.EventID(strings.Repeat("e", metadata.SpannerMaxOpaqueBytes+1))}, mutation: mutation, want: metadata.ErrResourceExhausted},
		{name: "oversized publication identity", parents: nil, payload: 0, publication: metadata.Publication{Repository: repo, Changeset: changesetA(t), ID: metadata.PublicationID(strings.Repeat("p", metadata.SpannerMaxOpaqueBytes+1)), Event: "e"}, mutation: mutation, want: metadata.ErrResourceExhausted},
		{name: "empty mutation key", parents: nil, payload: 0, publication: publication, mutation: metadata.Mutation{}, want: metadata.ErrInvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := metadata.PlanSpannerPublication(scope, test.mutation, test.publication, test.parents, test.payload)
			if err != test.want {
				t.Fatalf("plan error = %v, want %v", err, test.want)
			}
			if !reflect.DeepEqual(got, metadata.SpannerPublicationPlan{}) {
				t.Fatalf("error returned a partial plan: %+v", got)
			}
		})
	}
}

func TestPlanSpannerPublishRequestBindsCanonicalRequestAndParents(t *testing.T) {
	repo := repoA()
	scope := metadata.Scope{Repository: repo, Principal: "principal"}
	parents := []model.ChangesetID{changesetB(t), changesetA(t)}
	change, err := model.NewChangeset(model.ChangesetInput{RepoID: repo, Parents: parents, Message: []byte("canonical bytes")})
	if err != nil {
		t.Fatal(err)
	}
	request := metadata.PublishRequest{
		Mutation:  metadata.Mutation{Key: "request-bound", RequestDigest: [32]byte{8}},
		ID:        changesetA(t),
		Changeset: change,
		Event:     "request-event",
	}
	publication := metadata.Publication{Repository: repo, Changeset: request.ID, ID: "request-publication", Event: request.Event}
	plan, err := metadata.PlanSpannerPublishRequest(scope, request, publication)
	if err != nil {
		t.Fatalf("request-bound plan rejected: %v", err)
	}
	if len(plan.Parents) != len(parents) || plan.Budget.Reads != uint64(len(parents))+3 ||
		plan.Budget.ReadBytes != plan.Budget.Reads*metadata.SpannerMaxReadRowBytes ||
		plan.Budget.ReadBytes > metadata.SpannerMaxPublicationReadBytes {
		t.Fatalf("request parents/read budget = %d/%d/%d, want %d reads and bounded bytes", len(plan.Parents), plan.Budget.Reads, plan.Budget.ReadBytes, len(parents))
	}
	for i, id := range parents {
		want, err := metadata.SpannerPublicationKey(repo, id)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Parents[i] != want {
			t.Fatalf("parent %d key = %+v, want ordered key %+v", i, plan.Parents[i], want)
		}
	}

	badRepoChange, err := model.NewChangeset(model.ChangesetInput{RepoID: [16]byte{2}, Parents: parents})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		request   metadata.PublishRequest
		pub       metadata.Publication
		scope     metadata.Scope
		wantError error
	}{
		{name: "publication changeset mismatch", request: request, pub: metadata.Publication{Repository: repo, Changeset: changesetB(t), ID: publication.ID, Event: request.Event}, scope: scope, wantError: metadata.ErrInvalidArgument},
		{name: "event mismatch", request: request, pub: metadata.Publication{Repository: repo, Changeset: request.ID, ID: publication.ID, Event: "different-event"}, scope: scope, wantError: metadata.ErrInvalidArgument},
		{name: "request changeset repository mismatch", request: metadata.PublishRequest{Mutation: request.Mutation, ID: request.ID, Changeset: badRepoChange, Event: request.Event}, pub: publication, scope: scope, wantError: metadata.ErrInvalidArgument},
		{name: "scope repository mismatch", request: request, pub: metadata.Publication{Repository: [16]byte{2}, Changeset: request.ID, ID: publication.ID, Event: request.Event}, scope: scope, wantError: metadata.ErrInvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := metadata.PlanSpannerPublishRequest(test.scope, test.request, test.pub)
			if err != test.wantError {
				t.Fatalf("plan error = %v, want %v", err, test.wantError)
			}
			if !reflect.DeepEqual(got, metadata.SpannerPublicationPlan{}) {
				t.Fatalf("mismatched request returned partial plan: %+v", got)
			}
		})
	}
}

func TestEncodeSpannerDerivedParentsPreservesExactOrderedScope(t *testing.T) {
	repo := repoA()
	firstValue := treeValue(t, "43545000000101120fd69aec6d6bc30c93019e2849ab05d1245e26985f70fc07ee6daa41ae4028")
	secondValue := treeValue(t, "435450000001011111111111111111111111111111111111111111111111111111111111111111")
	output := metadata.DerivedResult{
		Identity: metadata.DerivedIdentity{Repository: repo, Changeset: changesetA(t), Kind: "output-tree", Version: 9},
		Value:    firstValue,
	}
	parents := []metadata.DerivedResult{
		{Identity: metadata.DerivedIdentity{Repository: repo, Changeset: changesetB(t), Kind: "source-tree", Version: 7}, Value: firstValue},
		{Identity: metadata.DerivedIdentity{Repository: repo, Changeset: changesetA(t), Kind: string([]byte{0xff, 0, 'k'}), Version: 0x01020304}, Value: secondValue},
	}
	write := metadata.DerivedWrite{Result: output, Parents: parents}
	got, err := metadata.EncodeSpannerDerivedParents(write)
	if err != nil {
		t.Fatalf("encode derived parents: %v", err)
	}
	want := make([]byte, 4)
	binary.BigEndian.PutUint32(want, uint32(len(parents)))
	for _, parent := range parents {
		want = append(want, parent.Identity.Repository[:]...)
		typed, err := parent.Identity.Changeset.TypedID().MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, typed...)
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(parent.Identity.Kind)))
		want = append(want, n[:]...)
		want = append(want, parent.Identity.Kind...)
		binary.BigEndian.PutUint32(n[:], parent.Identity.Version)
		want = append(want, n[:]...)
		want = append(want, parent.Value.Bytes()...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded parents differ from independent ordered frame:\n got %x\nwant %x", got, want)
	}
	if got[0] != 0 || got[1] != 0 || got[2] != 0 || got[3] != 2 {
		t.Fatalf("parent count is not U32BE two: %x", got[:4])
	}

	// Mutating the returned encoding cannot alter retained values or a later encoding.
	got[4] ^= 0xff
	reencoded, err := metadata.EncodeSpannerDerivedParents(write)
	if err != nil || !bytes.Equal(reencoded, want) {
		t.Fatalf("encoded bytes alias input state: err=%v got=%x want=%x", err, reencoded, want)
	}
	reordered := metadata.DerivedWrite{Result: output, Parents: []metadata.DerivedResult{parents[1], parents[0]}}
	reorderedBytes, err := metadata.EncodeSpannerDerivedParents(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reorderedBytes, want) {
		t.Fatal("parent encoding discarded causal order")
	}

	maxParents := make([]metadata.DerivedResult, int(model.MaxParents))
	for i := range maxParents {
		maxParents[i] = parents[i%len(parents)]
	}
	maxWrite := metadata.DerivedWrite{Result: output, Parents: maxParents}
	encodedMax, err := metadata.EncodeSpannerDerivedParents(maxWrite)
	if err != nil || binary.BigEndian.Uint32(encodedMax[:4]) != uint32(model.MaxParents) {
		t.Fatalf("maximum derived parent count rejected: bytes=%d err=%v", len(encodedMax), err)
	}
	tooMany := append(append([]metadata.DerivedResult(nil), maxParents...), parents[0])
	if got, err := metadata.EncodeSpannerDerivedParents(metadata.DerivedWrite{Result: output, Parents: tooMany}); err != metadata.ErrInvalidArgument || got != nil {
		t.Fatalf("maximum-plus-one derived parent error=%v bytes=%d", err, len(got))
	}
}

// CORE-04/SECURITY-01: these descriptors differ only in explicit versus
// physically implicit PK suffixes and in the position of a sequential field.
func TestSpannerSecondaryPhysicalRouting(t *testing.T) {
	for _, unique := range []bool{false, true} {
		for _, explicit := range []bool{false, true} {
			for _, sequential := range []bool{false, true} {
				for _, complete := range []bool{false, true} {
					name := fmt.Sprintf("unique=%t/explicit=%t/sequential=%t/complete=%t", unique, explicit, sequential, complete)
					t.Run(name, func(t *testing.T) {
						schema := metadata.SpannerSchema()
						row := schemaTable(t, &schema, "MutationResults")
						fields := []string{"Repository", "Operation"}
						if complete {
							fields = append(fields, "Principal", "Mutation")
						}
						row.Columns = append(row.Columns,
							metadata.SpannerColumn{Name: "ActionRoute", Type: metadata.SpannerBytes, MaxBytes: 32, Semantic: metadata.SpannerHash, HashOf: fields},
							metadata.SpannerColumn{Name: "CreatedAt", Type: metadata.SpannerInt64, Semantic: metadata.SpannerSequential})
						key := []string{"ActionRoute", "Repository", "Operation"}
						if explicit || complete {
							key = append(key, "Principal", "Mutation")
						}
						if sequential {
							key = append(key, "CreatedAt")
						}
						row.Indexes = append(row.Indexes, metadata.SpannerIndex{Name: "MutationTimeline", Key: key, Unique: unique})
						// A unique operation-only lookup admits at most two rows per repo.
						// A sequential component defeats that bound; a nonunique index
						// instead admits arbitrarily many implicit Principal/Mutation rows.
						safe := complete || unique && !explicit && !sequential
						issues := metadata.ReviewSpannerSchema(schema)
						ddl, err := metadata.SpannerDDL(schema)
						if safe {
							if len(issues) != 0 || err != nil || len(ddl) != 9 {
								t.Fatalf("safe secondary rejected: issues=%+v ddl=%v err=%v", issues, ddl, err)
							}
						} else if !hasSpannerIssue(issues, row.Name, "MutationTimeline", "routing hash omits logical key field") &&
							!hasSpannerIssue(issues, row.Name, "MutationTimeline", "sequential key precedes distributed row identity") {
							t.Fatalf("unsafe physical routing accepted: issues=%+v ddl=%v err=%v", issues, ddl, err)
						} else if err != metadata.ErrInvalidArgument || ddl != nil {
							t.Fatalf("unsafe secondary emitted DDL: %v %v", ddl, err)
						}
					})
				}
			}
		}
	}
	t.Run("shard needs full route before sequential field", func(t *testing.T) {
		for _, routeFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("routeFirst=%t", routeFirst), func(t *testing.T) {
				schema := metadata.SpannerSchema()
				row := schemaTable(t, &schema, "Outbox")
				row.Columns = append(row.Columns, metadata.SpannerColumn{Name: "CreatedAt", Type: metadata.SpannerInt64, Semantic: metadata.SpannerSequential})
				key := []string{"Shard", "Repository", "CreatedAt", "Route", "Event"}
				if routeFirst {
					key = []string{"Shard", "Repository", "Route", "CreatedAt", "Event"}
				}
				row.Indexes = append(row.Indexes, metadata.SpannerIndex{Name: "OutboxTimeline", Key: key})
				issues := metadata.ReviewSpannerSchema(schema)
				ddl, err := metadata.SpannerDDL(schema)
				if routeFirst {
					if len(issues) != 0 || err != nil || len(ddl) != 9 {
						t.Fatalf("distributed shard timeline rejected: %+v %v", issues, err)
					}
				} else {
					requireSpannerIssue(t, issues, "Outbox", "OutboxTimeline", "sequential key precedes distributed row identity")
					if ddl != nil || err != metadata.ErrInvalidArgument {
						t.Fatalf("sharded append edge emitted DDL: %v %v", ddl, err)
					}
				}
			})
		}
	})
}

// CORE-05/SECURITY-02: exercise every v1 key/index independently, rather than
// accepting validation caused only by a malformed hash or missing column.
func TestSpannerRequiredKeyIdentities(t *testing.T) {
	for _, baseline := range metadata.SpannerSchema().Tables {
		for _, mutation := range []string{"delete", "replace", "reorder", "extend"} {
			t.Run(baseline.Name+"/primary/"+mutation, func(t *testing.T) {
				schema := metadata.SpannerSchema()
				row := schemaTable(t, &schema, baseline.Name)
				switch mutation {
				case "delete":
					row.PrimaryKey = nil
				case "replace":
					row.PrimaryKey = []string{"Route", "Repository"}
					if row.Name == "Publications" {
						// Exact independent reviewer counterexample: this is itself
						// distributed, but disagrees with the fixed publication helper.
						row.PrimaryKey = []string{"PublicationRoute", "Repository", "Publication"}
					}
				case "reorder":
					row.PrimaryKey[1], row.PrimaryKey[2] = row.PrimaryKey[2], row.PrimaryKey[1]
				case "extend":
					row.Columns = append(row.Columns, metadata.SpannerColumn{Name: "ExtraIdentity", Type: metadata.SpannerBytes, MaxBytes: 16, Semantic: metadata.SpannerIdentity})
					row.PrimaryKey = append(row.PrimaryKey, "ExtraIdentity")
				}
				requireSpannerIssue(t, metadata.ReviewSpannerSchema(schema), row.Name, "PRIMARY KEY", "missing or incompatible required primary key")
				if ddl, err := metadata.SpannerDDL(schema); ddl != nil || err != metadata.ErrInvalidArgument {
					t.Fatalf("incompatible primary emitted DDL: %v %v", ddl, err)
				}
			})
		}
		for _, index := range baseline.Indexes {
			for _, mutation := range []string{"delete", "rename", "replace", "reorder", "extend", "uniqueness", "move table"} {
				t.Run(baseline.Name+"/"+index.Name+"/"+mutation, func(t *testing.T) {
					schema := metadata.SpannerSchema()
					row := schemaTable(t, &schema, baseline.Name)
					got := &row.Indexes[0]
					switch mutation {
					case "delete":
						row.Indexes = nil
					case "rename":
						got.Name += "Replacement"
					case "replace":
						got.Key = append([]string(nil), row.PrimaryKey...)
					case "reorder":
						got.Key[1], got.Key[2] = got.Key[2], got.Key[1]
					case "extend":
						row.Columns = append(row.Columns, metadata.SpannerColumn{Name: "LookupTag", Type: metadata.SpannerBytes, MaxBytes: 16, Semantic: metadata.SpannerValue})
						got.Key = append(got.Key, "LookupTag")
					case "uniqueness":
						got.Unique = !got.Unique
					case "move table":
						schemaTable(t, &schema, "Refs").Indexes = append(schemaTable(t, &schema, "Refs").Indexes, *got)
						row.Indexes = nil
					}
					requireSpannerIssue(t, metadata.ReviewSpannerSchema(schema), row.Name, index.Name, "missing or incompatible required index")
					if ddl, err := metadata.SpannerDDL(schema); ddl != nil || err != metadata.ErrInvalidArgument {
						t.Fatalf("incompatible required index emitted DDL: %v %v", ddl, err)
					}
				})
			}
		}
	}
	t.Run("safe additive descriptors and reordered declarations", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		row := schemaTable(t, &schema, "Publications")
		row.Columns = append(row.Columns, metadata.SpannerColumn{Name: "Note", Type: metadata.SpannerBytes, MaxBytes: 16, Semantic: metadata.SpannerValue})
		row.Indexes = append([]metadata.SpannerIndex{{Name: "PublicationsByChangeset", Key: []string{"Route", "Repository", "Changeset"}}}, row.Indexes...)
		for i, j := 0, len(row.Columns)-1; i < j; i, j = i+1, j-1 {
			row.Columns[i], row.Columns[j] = row.Columns[j], row.Columns[i]
		}
		schema.Tables[0], schema.Tables[1] = schema.Tables[1], schema.Tables[0]
		schema.Tables = append(schema.Tables, metadata.SpannerTable{Name: "Extra", PrimaryKey: []string{"Route", "Repository", "ID"}, Columns: []metadata.SpannerColumn{
			{Name: "Route", Type: metadata.SpannerBytes, MaxBytes: 32, Semantic: metadata.SpannerHash, HashOf: []string{"Repository", "ID"}},
			{Name: "Repository", Type: metadata.SpannerBytes, MaxBytes: 16, Semantic: metadata.SpannerRepository},
			{Name: "ID", Type: metadata.SpannerBytes, MaxBytes: 16, Semantic: metadata.SpannerIdentity},
		}})
		if issues := metadata.ReviewSpannerSchema(schema); len(issues) != 0 {
			t.Fatalf("safe additive schema rejected: %+v", issues)
		}
		if ddl, err := metadata.SpannerDDL(schema); err != nil || len(ddl) != 10 {
			t.Fatalf("safe additive DDL: %v %v", ddl, err)
		}
	})
}

// Preserve the exact CORE-02 required-index descriptors as negative witnesses
// too: C1 now rejects the extension even at the otherwise safe byte boundary.
func TestSpannerOriginalPhysicalKeyWitnesses(t *testing.T) {
	for _, bound := range []uint64{3757, 3758, 3856, ^uint64(0)} {
		for _, explicitPK := range []bool{false, true} {
			t.Run(fmt.Sprintf("bound=%d/explicitPK=%t", bound, explicitPK), func(t *testing.T) {
				schema := metadata.SpannerSchema()
				row := schemaTable(t, &schema, "Publications")
				row.Columns = append(row.Columns, metadata.SpannerColumn{Name: "LookupTag", Type: metadata.SpannerBytes, MaxBytes: bound, Semantic: metadata.SpannerValue})
				row.Indexes[0].Key = append(row.Indexes[0].Key, "LookupTag")
				if explicitPK {
					row.Indexes[0].Key = append(row.Indexes[0].Key, "Route")
				}
				issues := metadata.ReviewSpannerSchema(schema)
				requireSpannerIssue(t, issues, "Publications", "PublicationsByID", "missing or incompatible required index")
				if bound != 3757 {
					requireSpannerIssue(t, issues, "Publications", "PublicationsByID", "oversized key")
				}
				if ddl, err := metadata.SpannerDDL(schema); ddl != nil || err != metadata.ErrInvalidArgument {
					t.Fatalf("original incompatible descriptor emitted DDL: %v %v", ddl, err)
				}
			})
		}
	}
}

func TestSpannerV1KeyDDLContract(t *testing.T) {
	// Literal expectations are independent of SpannerSchema, which is also the
	// runtime baseline. Existing key-column golden tests bind helpers to these
	// same primary and publication-ID sequences.
	want := map[string]string{
		"Publications":    "PRIMARY KEY (`Route`, `Repository`, `Changeset`)",
		"EventBindings":   "PRIMARY KEY (`Route`, `Repository`, `Event`)",
		"MutationResults": "PRIMARY KEY (`Route`, `Repository`, `Principal`, `Operation`, `Mutation`)",
		"Outbox":          "PRIMARY KEY (`Route`, `Repository`, `Event`)",
		"Refs":            "PRIMARY KEY (`Route`, `Repository`, `Name`)",
		"DerivedMappings": "PRIMARY KEY (`Route`, `Repository`, `Changeset`, `Kind`, `Version`)",
	}
	ddl, err := metadata.SpannerDDL(metadata.SpannerSchema())
	if err != nil {
		t.Fatal(err)
	}
	for table, key := range want {
		t.Run(table, func(t *testing.T) {
			for _, statement := range ddl {
				if strings.HasPrefix(statement, "CREATE TABLE `"+table+"` (") && strings.HasSuffix(statement, key) {
					return
				}
			}
			t.Fatalf("missing v1 table/key contract: %s %s", table, key)
		})
	}
	for _, index := range []string{
		"CREATE UNIQUE INDEX `PublicationsByID` ON `Publications` (`PublicationRoute`, `Repository`, `Publication`)",
		"CREATE INDEX `OutboxPending` ON `Outbox` (`Shard`, `Repository`, `Acknowledged`, `Route`, `Event`)",
	} {
		t.Run(index, func(t *testing.T) {
			for _, statement := range ddl {
				if statement == index {
					return
				}
			}
			t.Fatalf("missing v1 index contract: %s", index)
		})
	}
}

// CORE-06/SECURITY-03: exact independent failing descriptors and assertions.
// A Value suffix still participates in UNIQUE identity. There can be many
// distinct admitted Tag values behind each of the two Operation-only routes.
// No sequential semantic or baseline descriptor is changed by this witness.
func TestIndependentUniqueValueSuffixDistribution(t *testing.T) {
	s := metadata.SpannerSchema()
	row := schemaTable(t, &s, "MutationResults")
	row.Columns = append(row.Columns,
		metadata.SpannerColumn{Name: "ActionRoute", Type: metadata.SpannerBytes, MaxBytes: 32, Semantic: metadata.SpannerHash, HashOf: []string{"Repository", "Operation"}},
		metadata.SpannerColumn{Name: "Tag", Type: metadata.SpannerBytes, MaxBytes: 128, Semantic: metadata.SpannerValue},
	)
	row.Indexes = append(row.Indexes, metadata.SpannerIndex{Name: "MutationTags", Unique: true, Key: []string{"ActionRoute", "Repository", "Operation", "Tag"}})
	issues := metadata.ReviewSpannerSchema(s)
	ddl, err := metadata.SpannerDDL(s)
	t.Logf("issues=%+v ddl_count=%d ddl_error=%v", issues, len(ddl), err)
	for _, statement := range ddl {
		t.Log(statement)
	}
	// The 256 distinct tags can be ordered record identifiers, digests or any
	// bounded exact Value. Each retains a distinct UNIQUE declared key.
	tags := make(map[string]bool)
	for i := 0; i < 256; i++ {
		tags[fmt.Sprintf("%0128d", i)] = true
	}
	t.Logf("distinct fixture tags=%d; each repository has only Publish=1/CASRef=2 leading ActionRoute hashes", len(tags))
	if len(issues) == 0 || err != metadata.ErrInvalidArgument || ddl != nil {
		t.Fatalf("unbounded unique-key multiplicity accepted behind finite Operation-only route: issues=%+v ddl_count=%d err=%v", issues, len(ddl), err)
	}
}

// Result remains the existing mandatory BYTES(512)/Value column. No semantic
// label is changed. A unique index can have arbitrarily many distinct Result
// values per operation, with the same two-valued route and implicit PK suffix.
func TestIndependentUniqueValueMultiplicity(t *testing.T) {
	s := metadata.SpannerSchema()
	r := schemaTable(t, &s, "MutationResults")
	r.Columns = append(r.Columns, metadata.SpannerColumn{Name: "ActionRoute", Type: metadata.SpannerBytes, MaxBytes: 32, Semantic: metadata.SpannerHash, HashOf: []string{"Repository", "Operation"}})
	r.Indexes = append(r.Indexes, metadata.SpannerIndex{Name: "MutationResultsByValue", Key: []string{"ActionRoute", "Repository", "Operation", "Result"}, Unique: true})
	issues := metadata.ReviewSpannerSchema(s)
	ddl, err := metadata.SpannerDDL(s)
	t.Logf("issues=%+v ddl_statements=%d err=%v", issues, len(ddl), err)
	for _, d := range ddl {
		if len(d) > 0 {
			t.Log(d)
		}
	}
	// Full logical identities and ordered result values can vary independently;
	// uniqueness does not cap multiplicity at two rows per repository.
	for i := 0; i < 3; i++ {
		t.Logf("admitted row family operation=1 principal=p%d mutation=m%d Result=%s", i, i, fmt.Sprintf("%016d", i))
	}
	if len(issues) == 0 || ddl != nil || err != metadata.ErrInvalidArgument {
		t.Fatalf("unique Value suffix permits many physical identities under an operation-only hash")
	}
}

func TestIndependentUniqueValuePhysicalWitness(t *testing.T) {
	routes := map[[32]byte]bool{}
	primary := map[[32]byte]bool{}
	tags := map[string]bool{}
	repo := repoA()
	for i := 0; i < 256; i++ {
		route := schemaRouteForTest("MutationResults", repo, []byte{byte(metadata.SpannerPublish)})
		key, err := metadata.SpannerMutationKey(repo, "principal", metadata.SpannerPublish, fmt.Sprintf("mutation-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		tag := fmt.Sprintf("%0128d", i)
		if len(tag) != 128 {
			t.Fatal("tag byte bound")
		}
		routes[route] = true
		primary[key.Route] = true
		tags[tag] = true
	}
	if len(routes) != 1 || len(primary) != 256 || len(tags) != 256 {
		t.Fatal("fixture did not preserve distinct identities")
	}
	t.Logf("256 distinct admitted mutation primary keys and distinct <=128-byte Tag values share %d ActionRoute; physical order is ActionRoute,Repository,Operation,Tag,Route,Principal,Mutation", len(routes))
}

func TestSpannerValueSuffixRouting(t *testing.T) {
	for _, kind := range []metadata.SpannerType{metadata.SpannerBytes, metadata.SpannerInt64, metadata.SpannerBool} {
		for _, unique := range []bool{false, true} {
			for _, layout := range []string{"operation only", "complete leading hash", "full route before value", "full route after value", "lookup identity hashed", "identity not hashed"} {
				t.Run(fmt.Sprintf("type=%d/unique=%t/%s", kind, unique, layout), func(t *testing.T) {
					s := metadata.SpannerSchema()
					row := schemaTable(t, &s, "MutationResults")
					value := metadata.SpannerColumn{Name: "Extra", Type: kind, Semantic: metadata.SpannerValue}
					if kind == metadata.SpannerBytes {
						value.MaxBytes = 1 // Even short BYTES has no Bool cardinality contract.
					}
					fields := []string{"Repository", "Operation"}
					key := []string{"ActionRoute", "Repository", "Operation", "Extra"}
					safe := unique && kind == metadata.SpannerBool
					switch layout {
					case "complete leading hash":
						fields = append(fields, "Principal", "Mutation")
						key = []string{"ActionRoute", "Repository", "Operation", "Principal", "Mutation", "Extra"}
						safe = true
					case "full route before value", "full route after value":
						key = []string{"Shard", "Repository", "Operation", "Route", "Extra"}
						if layout == "full route after value" {
							key[3], key[4] = key[4], key[3]
						}
						fields = append(fields, "Principal", "Mutation")
						key = append(key, "Principal", "Mutation")
						row.Columns = append(row.Columns, metadata.SpannerColumn{Name: "Shard", Type: metadata.SpannerInt64, Semantic: metadata.SpannerShard, HashOf: fields})
						safe = layout == "full route before value" || kind == metadata.SpannerBool
					case "lookup identity hashed", "identity not hashed":
						value.Semantic = metadata.SpannerIdentity
						if layout == "lookup identity hashed" {
							fields = append(fields, "Extra")
						}
						safe = unique && layout == "lookup identity hashed"
					}
					row.Columns = append(row.Columns, metadata.SpannerColumn{Name: "ActionRoute", Type: metadata.SpannerBytes, MaxBytes: 32, Semantic: metadata.SpannerHash, HashOf: fields}, value)
					row.Indexes = append(row.Indexes, metadata.SpannerIndex{Name: "ExtraValues", Unique: unique, Key: key})
					issues := metadata.ReviewSpannerSchema(s)
					ddl, err := metadata.SpannerDDL(s)
					if safe {
						if len(issues) != 0 || err != nil || len(ddl) != 9 {
							t.Fatalf("safe routing rejected: issues=%+v ddl=%v err=%v", issues, ddl, err)
						}
					} else if len(issues) == 0 || err != metadata.ErrInvalidArgument || ddl != nil {
						t.Fatalf("unsafe routing accepted: issues=%+v ddl=%v err=%v", issues, ddl, err)
					}
					if !safe && value.Semantic == metadata.SpannerValue && kind != metadata.SpannerBool {
						requireSpannerIssue(t, issues, row.Name, "ExtraValues", "unrestricted value precedes distributed row or lookup identity")
					}
				})
			}
		}
	}
}

func TestSpannerValueSuffixIndependentLookup(t *testing.T) {
	for _, kind := range []metadata.SpannerType{metadata.SpannerBytes, metadata.SpannerInt64} {
		for _, proof := range []string{"absent", "unique", "nonunique", "unrestricted suffix", "Bool suffix", "unhashed identity"} {
			t.Run(fmt.Sprintf("type=%d/%s", kind, proof), func(t *testing.T) {
				s := metadata.SpannerSchema()
				row := schemaTable(t, &s, "MutationResults")
				value := metadata.SpannerColumn{Name: "Extra", Type: kind, Semantic: metadata.SpannerValue}
				if kind == metadata.SpannerBytes {
					value.MaxBytes = 128
				}
				row.Columns = append(row.Columns,
					metadata.SpannerColumn{Name: "ActionRoute", Type: metadata.SpannerBytes, MaxBytes: 32, Semantic: metadata.SpannerHash, HashOf: []string{"Repository", "Operation"}},
					metadata.SpannerColumn{Name: "Filter", Type: metadata.SpannerBool, Semantic: metadata.SpannerValue}, value)
				row.Indexes = append(row.Indexes, metadata.SpannerIndex{Name: "ExtraValues", Unique: true, Key: []string{"ActionRoute", "Repository", "Operation", "Extra"}})
				lookup := metadata.SpannerIndex{Name: "Operations", Unique: proof != "nonunique", Key: []string{"ActionRoute", "Repository", "Operation"}}
				switch proof {
				case "unrestricted suffix":
					lookup.Key = append(lookup.Key, "Extra")
				case "Bool suffix":
					lookup.Key = append(lookup.Key, "Filter")
				case "unhashed identity":
					lookup.Key = append(lookup.Key, "Principal")
				}
				if proof != "absent" {
					row.Indexes = append(row.Indexes, lookup)
				}
				safe := proof == "unique" || proof == "Bool suffix"
				issues := metadata.ReviewSpannerSchema(s)
				ddl, err := metadata.SpannerDDL(s)
				if safe {
					if len(issues) != 0 || err != nil || len(ddl) != 10 {
						t.Fatalf("enforced bounded lookup rejected: %+v %v %v", issues, ddl, err)
					}
				} else {
					requireSpannerIssue(t, issues, row.Name, "ExtraValues", "unrestricted value precedes distributed row or lookup identity")
					if err != metadata.ErrInvalidArgument || ddl != nil {
						t.Fatalf("unsupported lookup emitted DDL: %v %v", ddl, err)
					}
				}
			})
		}
	}
}

func TestSpannerBooleanDimensionBounds(t *testing.T) {
	const reason = "multiple Boolean dimensions precede distributed row or bounded lookup identity"
	for _, dimensions := range []int{0, 1, 2, 8, 32, 64} {
		for _, proof := range []string{"none", "row before", "row after", "eligible zero", "eligible one", "ineligible two", "unrelated", "duplicate", "nonunique", "invalid route", "oversized lookup"} {
			t.Run(fmt.Sprintf("dimensions=%d/%s", dimensions, proof), func(t *testing.T) {
				s := metadata.SpannerSchema()
				row := *schemaTable(t, &s, "MutationResults")
				row.Name = "BooleanRows" // Isolate index cardinality from publication-cell limits.
				row.Columns = append(row.Columns,
					metadata.SpannerColumn{Name: "ActionRoute", Type: metadata.SpannerBytes, MaxBytes: 32, Semantic: metadata.SpannerHash, HashOf: []string{"Repository", "Operation"}},
					metadata.SpannerColumn{Name: "OtherRoute", Type: metadata.SpannerBytes, MaxBytes: 32, Semantic: metadata.SpannerHash, HashOf: []string{"Repository", "Principal"}},
					metadata.SpannerColumn{Name: "LookupFlag", Type: metadata.SpannerBool, Semantic: metadata.SpannerValue},
					metadata.SpannerColumn{Name: "OtherFlag", Type: metadata.SpannerBool, Semantic: metadata.SpannerValue})
				key := []string{"ActionRoute", "Repository", "Operation"}
				if proof == "row before" {
					key = append(key, "Route")
				}
				for i := 0; i < dimensions; i++ {
					name := fmt.Sprintf("Flag%d", i)
					row.Columns = append(row.Columns, metadata.SpannerColumn{Name: name, Type: metadata.SpannerBool, Semantic: metadata.SpannerValue})
					key = append(key, name)
				}
				if proof == "row after" {
					key = append(key, "Route")
				}
				safe := dimensions <= 1 || proof == "row before" || strings.HasPrefix(proof, "eligible")
				lookup := metadata.SpannerIndex{Name: "BooleanLookup", Unique: true, Key: []string{"ActionRoute", "Repository", "Operation"}}
				switch proof {
				case "eligible zero", "eligible one":
					key = append(key, "Result") // The independent lookup must cap the whole row family.
					if proof == "eligible one" {
						lookup.Key = append(lookup.Key, "LookupFlag")
					}
				case "ineligible two":
					key = append(key, "Result") // Prevent the target's zero/one-bit key certifying the lookup.
					lookup.Key = append(lookup.Key, "LookupFlag", "OtherFlag")
					safe = false
				case "unrelated":
					lookup.Key = []string{"OtherRoute", "Repository", "Principal"}
				case "duplicate":
					lookup.Key = append(lookup.Key, "LookupFlag", "LookupFlag")
					safe = false
				case "nonunique":
					lookup.Unique = false
					safe = false
				case "invalid route":
					schemaColumn(t, &row, "OtherRoute").HashOf = []string{"Repository", "Operation", "Operation"}
					lookup.Key[0] = "OtherRoute"
					safe = false
				case "oversized lookup":
					for i := 0; i < 12; i++ {
						name := fmt.Sprintf("ProofRoute%d", i)
						row.Columns = append(row.Columns, metadata.SpannerColumn{Name: name, Type: metadata.SpannerBytes, MaxBytes: 32, Semantic: metadata.SpannerHash, HashOf: []string{"Repository", "Operation"}})
						lookup.Key = append(lookup.Key, name)
					}
					safe = false
				}
				// Large shapes retain overflow/rejection coverage, not isolated
				// cardinality evidence: they also exceed the provider column cap.
				safe = safe && dimensions < 32
				row.Indexes = []metadata.SpannerIndex{{Name: "BooleanValues", Unique: true, Key: key}}
				if proof != "none" && proof != "row before" && proof != "row after" {
					row.Indexes = append(row.Indexes, lookup)
				}
				s.Tables = append(s.Tables, row)
				issues := metadata.ReviewSpannerSchema(s)
				ddl, err := metadata.SpannerDDL(s)
				if safe {
					if len(issues) != 0 || err != nil || len(ddl) < 10 {
						t.Fatalf("supported Boolean shape rejected: %+v %v %v", issues, ddl, err)
					}
				} else if len(issues) == 0 || err != metadata.ErrInvalidArgument || ddl != nil {
					t.Fatalf("unsupported Boolean shape admitted: %+v %v %v", issues, ddl, err)
				}
				if dimensions > 1 && proof != "row before" && !strings.HasPrefix(proof, "eligible") {
					requireSpannerIssue(t, issues, row.Name, "BooleanValues", reason)
				}
				if proof == "duplicate" && hasSpannerIssue(issues, row.Name, "BooleanLookup", reason) {
					t.Fatal("repeated references to one Boolean counted as independent dimensions")
				}
				if dimensions == 2 && proof == "none" && len(issues) != 1 {
					t.Fatalf("small two-Boolean witness must fail only for cardinality: %+v", issues)
				}
				if dimensions >= 32 {
					requireSpannerIssue(t, issues, row.Name, "BooleanValues", "too many physical key columns")
				}
				for _, issue := range issues {
					if issue.Key == "transaction" || issue.Reason == "oversized key" || dimensions < 32 && issue.Reason == "too many physical key columns" && !(proof == "oversized lookup" && issue.Key == "BooleanLookup") {
						t.Fatalf("cardinality fixture confounded by physical/publication budget: %+v", issues)
					}
				}
			})
		}
	}
}

func TestSpannerOriginalBooleanCardinalityWitness(t *testing.T) {
	s := metadata.SpannerSchema()
	row := schemaTable(t, &s, "MutationResults")
	row.Columns = append(row.Columns, metadata.SpannerColumn{Name: "ActionRoute", Type: metadata.SpannerBytes, MaxBytes: 32, Semantic: metadata.SpannerHash, HashOf: []string{"Repository", "Operation"}})
	key := []string{"ActionRoute", "Repository", "Operation"}
	for i := 0; i < 32; i++ {
		name := fmt.Sprintf("Flag%d", i)
		row.Columns = append(row.Columns, metadata.SpannerColumn{Name: name, Type: metadata.SpannerBool, Semantic: metadata.SpannerValue})
		key = append(key, name)
	}
	row.Indexes = append(row.Indexes, metadata.SpannerIndex{Name: "BooleanValues", Unique: true, Key: key})
	issues := metadata.ReviewSpannerSchema(s)
	ddl, err := metadata.SpannerDDL(s)
	requireSpannerIssue(t, issues, row.Name, "BooleanValues", "multiple Boolean dimensions precede distributed row or bounded lookup identity")
	requireSpannerIssue(t, issues, row.Name, "BooleanValues", "too many physical key columns")
	if err != metadata.ErrInvalidArgument || ddl != nil {
		t.Fatalf("original 32-Bool witness must reject; small matrix cases isolate cardinality: issues=%+v ddl=%v err=%v", issues, ddl, err)
	}
}

func TestSpannerIdentifierNamespaces(t *testing.T) {
	for _, kind := range []string{"column", "table", "index", "table after index", "index before table"} {
		for _, collision := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/collision=%t", kind, collision), func(t *testing.T) {
				s := metadata.SpannerSchema()
				row := schemaTable(t, &s, "Refs")
				name, want := "NameExtra", ""
				switch kind {
				case "column":
					if collision {
						name = "name"
					}
					row.Columns = append(row.Columns, metadata.SpannerColumn{Name: name, Type: metadata.SpannerBytes, MaxBytes: 1, Semantic: metadata.SpannerValue})
					want = "`" + name + "` BYTES(1) NOT NULL"
				case "table", "table after index":
					if collision {
						name = "refs"
						if kind == "table after index" {
							name = "publicationsbyid"
						}
					}
					copy := *row
					copy.Name = name
					s.Tables = append(s.Tables, copy)
					want = "CREATE TABLE `" + name + "`"
				case "index", "index before table":
					if collision {
						name = "publicationsbyid"
						if kind == "index before table" {
							name = "refs"
						}
					}
					if kind == "index before table" {
						row = schemaTable(t, &s, "Publications")
					}
					row.Indexes = append(row.Indexes, metadata.SpannerIndex{Name: name, Key: append([]string(nil), row.PrimaryKey...)})
					want = "CREATE INDEX `" + name + "` ON `" + row.Name + "`"
				}
				issues := metadata.ReviewSpannerSchema(s)
				ddl, err := metadata.SpannerDDL(s)
				if collision {
					if len(issues) != 1 || !strings.Contains(issues[0].Reason, "duplicate") || err != metadata.ErrInvalidArgument || ddl != nil {
						t.Fatalf("collision admitted or confounded: %+v %v %v", issues, ddl, err)
					}
				} else if len(issues) != 0 || err != nil || !strings.Contains(strings.Join(ddl, "\n"), want) {
					t.Fatalf("distinct spelling not preserved: %+v %v %v", issues, ddl, err)
				}
			})
		}
	}
}

func TestSpannerPhysicalKeyColumnLimits(t *testing.T) {
	for _, kind := range []string{"primary", "secondary explicit", "secondary implicit"} {
		for _, count := range []int{16, 17} {
			t.Run(fmt.Sprintf("%s/columns=%d", kind, count), func(t *testing.T) {
				s := metadata.SpannerSchema()
				row := metadata.SpannerTable{Name: "KeyColumnRows", PrimaryKey: []string{"Route", "Repository", "ID"}, Columns: []metadata.SpannerColumn{
					{Name: "Route", Type: metadata.SpannerBytes, MaxBytes: 32, Semantic: metadata.SpannerHash, HashOf: []string{"Repository", "ID"}},
					{Name: "Repository", Type: metadata.SpannerBytes, MaxBytes: 16, Semantic: metadata.SpannerRepository},
					{Name: "ID", Type: metadata.SpannerBytes, MaxBytes: 16, Semantic: metadata.SpannerIdentity},
				}}
				key := append([]string(nil), row.PrimaryKey...)
				n := count - 3
				if kind == "secondary implicit" {
					row.Columns = append(row.Columns, metadata.SpannerColumn{Name: "IndexRoute", Type: metadata.SpannerBytes, MaxBytes: 32, Semantic: metadata.SpannerHash, HashOf: []string{"Repository", "ID"}})
					key[0] = "IndexRoute" // Route is appended implicitly, exactly once.
					n--
				}
				for i := 0; i < n; i++ {
					name := fmt.Sprintf("Flag%d", i)
					column := metadata.SpannerColumn{Name: name, Type: metadata.SpannerBool, Semantic: metadata.SpannerValue}
					if kind == "primary" {
						column = metadata.SpannerColumn{Name: name, Type: metadata.SpannerBytes, MaxBytes: 1, Semantic: metadata.SpannerIdentity}
						row.Columns[0].HashOf = append(row.Columns[0].HashOf, name)
					}
					row.Columns = append(row.Columns, column)
					key = append(key, name)
				}
				keyName := "PRIMARY KEY"
				if kind == "primary" {
					row.PrimaryKey = key
				} else {
					keyName = "KeyColumnValues"
					row.Indexes = []metadata.SpannerIndex{{Name: keyName, Unique: true, Key: key}}
				}
				s.Tables = append(s.Tables, row)
				issues := metadata.ReviewSpannerSchema(s)
				ddl, err := metadata.SpannerDDL(s)
				t.Logf("declared=%d effective=%d issues=%+v", len(key), count, issues)
				if count == 16 {
					if len(issues) != 0 || err != nil || len(ddl) < 9 {
						t.Fatalf("16-column control rejected: %+v %v %v", issues, ddl, err)
					}
				} else {
					requireSpannerIssue(t, issues, row.Name, keyName, "too many physical key columns")
					if len(issues) != 1 || err != metadata.ErrInvalidArgument || ddl != nil {
						t.Fatalf("17-column rejection confounded: %+v %v %v", issues, ddl, err)
					}
				}
			})
		}
	}
}
