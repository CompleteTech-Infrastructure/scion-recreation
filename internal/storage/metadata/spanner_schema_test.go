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
	t.Run("zero bound", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		schemaColumn(t, schemaTable(t, &schema, "Publications"), "Parents").MaxBytes = 0
		requireSpannerIssue(t, metadata.ReviewSpannerSchema(schema), "Publications", "Parents", "unbounded or oversized row/type")
	})

	t.Run("single type larger than row limit", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		column := schemaColumn(t, schemaTable(t, &schema, "Publications"), "Parents")
		column.MaxBytes = metadata.SpannerMaxRowBytes + 1
		requireSpannerIssue(t, metadata.ReviewSpannerSchema(schema), "Publications", "Parents", "unbounded or oversized row/type")
	})

	t.Run("aggregate row exceeds row limit", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		refs := schemaTable(t, &schema, "Refs")
		schemaColumn(t, refs, "Name").MaxBytes = 140 << 10
		schemaColumn(t, refs, "Target").MaxBytes = 140 << 10
		requireSpannerIssue(t, metadata.ReviewSpannerSchema(schema), "Refs", "Target", "unbounded or oversized row/type")
	})

	t.Run("canonical payload cannot be stored in metadata row", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		schemaColumn(t, schemaTable(t, &schema, "Publications"), "Parents").Semantic = metadata.SpannerCanonicalPayload
		requireSpannerIssue(t, metadata.ReviewSpannerSchema(schema), "Publications", "Parents", "canonical payload belongs in object storage")
	})

	t.Run("key byte limit", func(t *testing.T) {
		schema := metadata.SpannerSchema()
		schemaColumn(t, schemaTable(t, &schema, "Refs"), "Name").MaxBytes = metadata.SpannerMaxKeyBytes
		requireSpannerIssue(t, metadata.ReviewSpannerSchema(schema), "Refs", "PRIMARY KEY", "oversized key")
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
