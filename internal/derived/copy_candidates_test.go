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

func TestTreeExactCopyIndexBindingAndEnumeration(t *testing.T) {
	source, rows, ids := copyFixture(t)
	empty, root, err := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil); if err != nil { t.Fatal(err) }
	frames := map[TreePageID][]byte{root: empty}
	for _, row := range rows {
		id, _ := row.Target()
		next, added, err := SetTreeLeaf(context.Background(), root, frames, row.Path(), byte(row.Tag()), id, TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes})
		if err != nil { t.Fatal(err) }
		for id, frame := range added { frames[id] = frame }; root = next
	}
	raw, err := root.MarshalBinary(); if err != nil { t.Fatal(err) }
	value, err := metadata.NewDerivedValueID(raw); if err != nil { t.Fatal(err) }
	identity := metadata.DerivedIdentity{Repository: [16]byte{1}, Changeset: source, Kind: "TREE", Version: 1}
	record := metadata.DerivedResult{Identity: identity, Value: value}
	budget := TreeEntriesBudget{Graph: TreeGraphBudget{4096, 4096*MaxTreePageBytes, 64<<20}, Entries: 4, PathBytes: 8}
	index, usage, err := NewTreeExactCopyIndex(context.Background(), identity, record, frames, budget)
	if err != nil || usage.Terminals != 4 { t.Fatal(index, usage, err) }
	got, err := index.Lookup(context.Background(), ids[0], 3)
	if err != nil || got.Source != source || len(got.Paths) != 3 || string(got.Paths[0].Bytes()) != "A" || string(got.Paths[1].Bytes()) != "a" || string(got.Paths[2].Bytes()) != "\xff" { t.Fatal(got, err) }
	// Successful index has no mutable frame dependency.
	frames[root][0] ^= 1
	if again, err := index.Lookup(context.Background(), ids[0], 3); err != nil || len(again.Paths) != 3 { t.Fatal(again, err) }
	if index, _, err := NewTreeExactCopyIndex(context.Background(), identity, record, frames, budget); err != ErrTreePage || index != nil { t.Fatal(index, err) }
	frames[root][0] ^= 1
	for _, which := range []string{"repo", "source", "kind", "version", "value"} {
		bad := record
		switch which {
		case "repo": bad.Identity.Repository[0] ^= 1
		case "source": bad.Identity.Changeset = model.ChangesetID{}
		case "kind": bad.Identity.Kind = "COPY"
		case "version": bad.Identity.Version = 2
		case "value": bad.Value = metadata.DerivedValueID{}
		}
		if index, usage, err := NewTreeExactCopyIndex(context.Background(), identity, bad, frames, budget); err != metadata.ErrInvalidArgument || index != nil || usage != (TreeGraphUsage{}) { t.Fatal(which, index, usage, err) }
	}
	for _, which := range []string{"entries", "paths", "reads", "visits"} {
		b := budget
		switch which { case "entries": b.Entries = 3; case "paths": b.PathBytes = 7; case "reads": b.Graph.PageBytes = 1; case "visits": b.Graph.Visits = 1 }
		if index, _, err := NewTreeExactCopyIndex(context.Background(), identity, record, frames, b); err != metadata.ErrResourceExhausted || index != nil { t.Fatal(which, index, err) }
	}
	if index, _, err := NewTreeExactCopyIndex(context.Background(), identity, record, nil, budget); err != ErrTreePageMissing || index != nil { t.Fatal(index, err) }
	if index, _, err := NewTreeExactCopyIndex(nil, identity, record, frames, budget); err != metadata.ErrInvalidArgument || index != nil { t.Fatal(index, err) }
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if index, _, err := NewTreeExactCopyIndex(ctx, identity, record, frames, budget); err != context.Canceled || index != nil { t.Fatal(index, err) }
}

func TestExactCopiesOfPathExcludesSourceBeforeBudget(t *testing.T) {
	source, rows, _ := copyFixture(t)
	index, err := NewExactCopyIndex(context.Background(), source, rows, ExactCopyBudget{4,4}); if err != nil { t.Fatal(err) }
	for _, tc := range []struct { row int; want []string }{{0, []string{"a", "\xff"}}, {1, []string{"A", "\xff"}}, {2, nil}, {3, []string{"A", "a"}}} {
		got, err := index.CopiesOfPath(context.Background(), rows[tc.row].Path(), 2)
		if err != nil || got.Source != source || len(got.Paths) != len(tc.want) { t.Fatal(got, err) }
		for i, want := range tc.want { if string(got.Paths[i].Bytes()) != want { t.Fatal(got, tc.want) } }
	}
	if got, err := index.CopiesOfPath(context.Background(), rows[0].Path(), 1); err != metadata.ErrResourceExhausted || got.Source != (model.ChangesetID{}) || got.Paths != nil { t.Fatal(got, err) }
	path := rows[0].Path(); rows[0] = model.Operation{}
	got, err := index.CopiesOfPath(context.Background(), path, 2); if err != nil { t.Fatal(err) }
	got.Paths[0] = model.Path{}
	if again, err := index.CopiesOfPath(context.Background(), path, 2); err != nil || string(again.Paths[0].Bytes()) != "a" { t.Fatal(again, err) }
	missing, _ := model.NewPath([]byte("missing"))
	if got, err := index.CopiesOfPath(context.Background(), missing, 2); err != metadata.ErrNotFound || got.Source != (model.ChangesetID{}) || got.Paths != nil { t.Fatal(got, err) }
	if got, err := index.CopiesOfPath(context.Background(), model.Path{}, 2); err != metadata.ErrInvalidArgument || got.Paths != nil { t.Fatal(got, err) }
	for _, limit := range []uint64{0,4097} { if got, err := index.CopiesOfPath(context.Background(), path, limit); err != metadata.ErrInvalidArgument || got.Paths != nil { t.Fatal(got, err) } }
	for _, invalid := range []*ExactCopyIndex{nil, {}} { if got, err := invalid.CopiesOfPath(context.Background(), path, 2); err != metadata.ErrInvalidArgument || got.Paths != nil { t.Fatal(got, err) } }
	if got, err := index.CopiesOfPath(nil, path, 2); err != metadata.ErrInvalidArgument || got.Paths != nil { t.Fatal(got, err) }
}

type copyCancelContext struct { context.Context; calls, cancelAt int }
func (c *copyCancelContext) Err() error { c.calls++; if c.calls >= c.cancelAt { return context.Canceled }; return nil }

func TestExactCopiesOfPathCancellationDiscardsMatches(t *testing.T) {
	source, rows, _ := copyFixture(t)
	index, err := NewExactCopyIndex(context.Background(), source, rows, ExactCopyBudget{4,4}); if err != nil { t.Fatal(err) }
	// Entry check, three bucket paths (including excluded source), final check.
	// At four and five, at least one match was already appended privately.
	for _, at := range []int{1,3,4,5} {
		ctx := &copyCancelContext{Context: context.Background(), cancelAt: at}
		got, err := index.CopiesOfPath(ctx, rows[0].Path(), 2)
		if err != context.Canceled || got.Source != (model.ChangesetID{}) || got.Paths != nil { t.Fatal(at, got, err) }
	}
}

func TestCanonicalExactCopyIndexBindsSelectedSource(t *testing.T) {
	ctx := context.Background(); repo := [16]byte{7}
	blob, frame := treeCanonicalBlob(t, []byte("x\x00"))
	blobs := map[model.BlobID][]byte{blob:frame}
	a, _ := model.NewPath([]byte("a")); b, _ := model.NewPath([]byte("\xff"))
	regular, _ := model.NewOperation(a, model.SetRegular, &blob)
	symlink, _ := model.NewOperation(b, model.SetSymlink, &blob)
	remove, _ := model.NewOperation(b, model.Delete, nil)
	root := treeReplaySource(t, model.ChangesetInput{RepoID:repo,Operations:[]model.Operation{regular,symlink}})
	other := treeReplaySource(t, model.ChangesetInput{RepoID:repo})
	merge := treeReplaySource(t, model.ChangesetInput{RepoID:repo,Parents:[]model.ChangesetID{root.ID,other.ID}})
	last := treeReplaySource(t, model.ChangesetInput{RepoID:repo,Parents:[]model.ChangesetID{merge.ID},Operations:[]model.Operation{remove}})
	sources := []TreeSourceFrame{root,other,merge,last}
	graph := TreeObjectGraphBudget{graphTestBudget(),1<<20}
	step := TreeCheckedWriteBudget{graph,graph,TreeChangesetBudget{TreeRewriteBudget{4096,4096*MaxTreePageBytes,4096*MaxTreePageBytes},4096,model.MaxChangesetPayload}}
	replay := TreeReplayBudget{4,1<<20,4096,4096*MaxTreePageBytes,step}
	entries := TreeEntriesBudget{graphTestBudget(),2,4}
	for _, target := range []model.ChangesetID{root.ID,merge.ID} {
		index, used, err := NewCanonicalExactCopyIndex(ctx,repo,target,sources,blobs,replay,entries)
		if err != nil || index == nil || used.Replay.Sources != 4 || used.Enumeration.Visits == 0 { t.Fatal(index,used,err) }
		matches, err := index.CopiesOfPath(ctx,a,1)
		if err != nil || matches.Source != target || len(matches.Paths) != 1 || matches.Paths[0] != b { t.Fatal(matches,err) }
	}
	index, _, err := NewCanonicalExactCopyIndex(ctx,repo,last.ID,sources,blobs,replay,entries)
	if err != nil { t.Fatal(err) }
	matches, err := index.CopiesOfPath(ctx,a,1)
	if err != nil || len(matches.Paths) != 0 || matches.Source != last.ID { t.Fatal(matches,err) }
	// Later source corruption rejects an already computable earlier target.
	bad := append([]TreeSourceFrame(nil),sources...)
	bad[3].Frame = append([]byte(nil),last.Frame...); bad[3].Frame[len(last.Frame)-1] ^= 1
	if index, _, err := NewCanonicalExactCopyIndex(ctx,repo,root.ID,bad,blobs,replay,entries); err == nil || index != nil { t.Fatal(index,err) }
	if index, _, err := NewCanonicalExactCopyIndex(ctx,repo,root.ID,sources,nil,replay,entries); err == nil || index != nil { t.Fatal(index,err) }
	if index, _, err := NewCanonicalExactCopyIndex(ctx,repo,merge.ID,[]TreeSourceFrame{root,merge},blobs,replay,entries); err != metadata.ErrFailedPrecondition || index != nil { t.Fatal(index,err) }
	missing := treeReplaySource(t,model.ChangesetInput{RepoID:[16]byte{9}})
	if index, used, err := NewCanonicalExactCopyIndex(ctx,repo,missing.ID,sources,blobs,replay,entries); err != metadata.ErrNotFound || index != nil || used.Replay.Sources != 4 { t.Fatal(index,used,err) }
	short := entries; short.Entries = 1
	if index, used, err := NewCanonicalExactCopyIndex(ctx,repo,root.ID,sources,blobs,replay,short); err != metadata.ErrResourceExhausted || index != nil || used.Replay.Sources != 4 { t.Fatal(index,used,err) }
	shortReplay := replay; shortReplay.Sources = 3
	if index, _, err := NewCanonicalExactCopyIndex(ctx,repo,root.ID,sources,blobs,shortReplay,entries); err != metadata.ErrResourceExhausted || index != nil { t.Fatal(index,err) }
	if index, _, err := NewCanonicalExactCopyIndex(nil,repo,root.ID,sources,blobs,replay,entries); err != metadata.ErrInvalidArgument || index != nil { t.Fatal(index,err) }
	cancelled, cancel := context.WithCancel(ctx); cancel()
	if index, _, err := NewCanonicalExactCopyIndex(cancelled,repo,root.ID,sources,blobs,replay,entries); err != context.Canceled || index != nil { t.Fatal(index,err) }
	// Index must not retain mutable supplied blob/source frames.
	frame[0] ^= 1; sources[0].Frame[0] ^= 1
	matches, err = index.CopiesOfPath(ctx,a,1)
	if err != nil || matches.Source != last.ID || len(matches.Paths) != 0 { t.Fatal(matches,err) }
}
