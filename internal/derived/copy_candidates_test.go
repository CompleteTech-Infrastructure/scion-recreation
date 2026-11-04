package derived

import (
	"context"
	"testing"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

func copyFixture(t *testing.T) (model.ChangesetID, []model.Operation, []model.BlobID) {
	t.Helper()
	sourceTID, err := model.NewTypedID(model.ChangesetKind, [32]byte{1}); if err != nil { t.Fatal(err) }
	source, err := model.NewChangesetID(sourceTID); if err != nil { t.Fatal(err) }
	var ids []model.BlobID
	for i := byte(1); i <= 3; i++ {
		tid, err := model.NewTypedID(model.BlobKind, [32]byte{i}); if err != nil { t.Fatal(err) }
		blob, err := model.NewBlobID(tid); if err != nil { t.Fatal(err) }; ids = append(ids, blob)
	}
	var rows []model.Operation
	for i, path := range []string{"A", "a", "z", "\xff"} {
		p, err := model.NewPath([]byte(path)); if err != nil { t.Fatal(err) }
		tag := model.SetRegular; if i == 1 { tag = model.SetExecutable }; if i == 3 { tag = model.SetSymlink }
		id := ids[0]; if i == 2 { id = ids[1] }
		op, err := model.NewOperation(p, tag, &id); if err != nil { t.Fatal(err) }; rows = append(rows, op)
	}
	return source, rows, ids
}

func TestExactCopyIndexIdentityOrderAndOwnership(t *testing.T) {
	source, rows, ids := copyFixture(t)
	index, err := NewExactCopyIndex(context.Background(), source, rows, ExactCopyBudget{4, 4})
	if err != nil { t.Fatal(err) }
	rows[0] = model.Operation{}
	for i, want := range [][]string{{"A", "a", "\xff"}, {"z"}, nil} {
		got, err := index.Lookup(context.Background(), ids[i], 3)
		if err != nil || got.Source != source || len(got.Paths) != len(want) { t.Fatal(got, err) }
		for j, path := range want { if string(got.Paths[j].Bytes()) != path { t.Fatal(got.Paths, want) } }
	}
	got, _ := index.Lookup(context.Background(), ids[0], 3)
	got.Paths[0] = model.Path{}
	again, err := index.Lookup(context.Background(), ids[0], 3)
	if err != nil || string(again.Paths[0].Bytes()) != "A" { t.Fatal(again, err) }
	if got, err := index.Lookup(context.Background(), ids[0], 2); err != metadata.ErrResourceExhausted || got.Source != (model.ChangesetID{}) || got.Paths != nil { t.Fatal(got, err) }
}

func TestExactCopyIndexAdmissionAndInvalidRows(t *testing.T) {
	source, rows, ids := copyFixture(t)
	for _, budget := range []ExactCopyBudget{{3, 4}, {4, 3}} {
		if index, err := NewExactCopyIndex(context.Background(), source, rows, budget); err != metadata.ErrResourceExhausted || index != nil { t.Fatal(index, err) }
	}
	deleted, err := model.NewOperation(rows[0].Path(), model.Delete, nil); if err != nil { t.Fatal(err) }
	for _, bad := range [][]model.Operation{{rows[0], rows[0]}, {rows[1], rows[0]}, {{}}, {deleted}} {
		if index, err := NewExactCopyIndex(context.Background(), source, bad, ExactCopyBudget{4, 4}); err != metadata.ErrInvalidArgument || index != nil { t.Fatal(index, err) }
	}
	for _, budget := range []ExactCopyBudget{{}, {4097, 4}, {4, 65<<20}} {
		if index, err := NewExactCopyIndex(context.Background(), source, nil, budget); err != metadata.ErrInvalidArgument || index != nil { t.Fatal(index, err) }
	}
	if index, err := NewExactCopyIndex(context.Background(), model.ChangesetID{}, rows, ExactCopyBudget{4, 4}); err != metadata.ErrInvalidArgument || index != nil { t.Fatal(index, err) }
	index, err := NewExactCopyIndex(context.Background(), source, nil, ExactCopyBudget{1, 1}); if err != nil { t.Fatal(err) }
	if got, err := index.Lookup(context.Background(), ids[0], 1); err != nil || got.Source != source || got.Paths != nil { t.Fatal(got, err) }
	for _, limit := range []uint64{0, 4097} { if got, err := index.Lookup(context.Background(), ids[0], limit); err != metadata.ErrInvalidArgument || got.Paths != nil { t.Fatal(got, err) } }
	var zero *ExactCopyIndex
	if got, err := zero.Lookup(context.Background(), ids[0], 1); err != metadata.ErrInvalidArgument || got.Paths != nil { t.Fatal(got, err) }
	if got, err := index.Lookup(nil, ids[0], 1); err != metadata.ErrInvalidArgument || got.Paths != nil { t.Fatal(got, err) }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if got, err := NewExactCopyIndex(ctx, source, rows, ExactCopyBudget{4, 4}); err != context.Canceled || got != nil { t.Fatal(got, err) }
	if got, err := index.Lookup(ctx, ids[0], 1); err != context.Canceled || got.Paths != nil { t.Fatal(got, err) }
}
