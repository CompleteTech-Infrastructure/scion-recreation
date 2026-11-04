package search

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

type pathCancelContext struct { context.Context; calls, stop int }
func (c *pathCancelContext) Err() error { c.calls++; if c.stop > 0 && c.calls >= c.stop { return context.Canceled }; return nil }

func TestCanonicalPathSnapshotRevisionAndPrivatePrefix(t *testing.T) {
	ctx := context.Background(); repo := [16]byte{8}
	blob, err := model.HashBlob(ctx, 0, bytes.NewReader(nil)); if err != nil { t.Fatal(err) }
	var encoded bytes.Buffer; if err := model.EncodeBlob(ctx, &encoded, 0, bytes.NewReader(nil)); err != nil { t.Fatal(err) }
	blobs := map[model.BlobID][]byte{blob: encoded.Bytes()}
	row := func(raw string, tag model.OperationTag) model.Operation {
		p, err := model.NewPath([]byte(raw)); if err != nil { t.Fatal(err) }
		var target *model.BlobID; if tag != model.Delete { target = &blob }
		op, err := model.NewOperation(p, tag, target); if err != nil { t.Fatal(err) }; return op
	}
	source := func(change model.ChangesetInput) derived.TreeSourceFrame {
		v, err := model.NewChangeset(change); if err != nil { t.Fatal(err) }
		id, err := model.HashChangeset(ctx, v); if err != nil { t.Fatal(err) }
		var frame bytes.Buffer; if err := model.EncodeChangeset(ctx, &frame, v); err != nil { t.Fatal(err) }
		return derived.TreeSourceFrame{ID: id, Frame: frame.Bytes()}
	}
	literal := row("*.go", model.SetRegular); a := row("a/b", model.SetExecutable); az := row("ab", model.SetRegular); z := row("z/\xff", model.SetSymlink)
	root := source(model.ChangesetInput{RepoID: repo, Operations: []model.Operation{literal, a, az}})
	left := source(model.ChangesetInput{RepoID: repo, Parents: []model.ChangesetID{root.ID}, Operations: []model.Operation{row("a/b", model.Delete), z}})
	right := source(model.ChangesetInput{RepoID: repo, Parents: []model.ChangesetID{root.ID}})
	merge := source(model.ChangesetInput{RepoID: repo, Parents: []model.ChangesetID{left.ID, right.ID}})
	sources := []derived.TreeSourceFrame{root, left, right, merge}
	var sourceBytes uint64; for _, s := range sources { sourceBytes += uint64(len(s.Frame)) }
	graph := derived.TreeGraphBudget{Visits: 4096, PageBytes: 4096*derived.MaxTreePageBytes, ContextBytes: 64<<20}
	objects := derived.TreeObjectGraphBudget{Graph: graph, BlobBytes: 1<<20}
	step := derived.TreeCheckedWriteBudget{Parent: objects, Candidate: objects, Rewrite: derived.TreeChangesetBudget{Rewrite: derived.TreeRewriteBudget{Pages: 4096, ReadBytes: 4096*derived.MaxTreePageBytes, WriteBytes: 4096*derived.MaxTreePageBytes}, Operations: 4096, InputBytes: model.MaxChangesetPayload}}
	budget := PathSnapshotBudget{Replay: derived.TreeReplayBudget{Sources: 4, SourceBytes: sourceBytes, Pages: 4096, PageBytes: 4096*derived.MaxTreePageBytes, Step: step}, Snapshot: derived.TreeEntriesBudget{Graph: graph, Entries: 3, PathBytes: 18}}
	snapshot, used, err := BuildCanonicalPathSnapshot(ctx, repo, merge.ID, sources, blobs, budget)
	if err != nil || snapshot == nil || used.Replay.Sources != 4 { t.Fatalf("snapshot: %+v %v", used, err) }
	query := PathPrefixBudget{Paths: 3, Bytes: 9, Matches: 3}
	want := []model.Operation{literal, az, z}
	out, usage, err := snapshot.Prefix(ctx, repo, merge.ID, nil, query)
	if err != nil || !reflect.DeepEqual(out, want) || usage != (PathPrefixUsage{3,9}) { t.Fatalf("deleted path resurrected: %+v %+v %v", out, usage, err) }
	out[0] = z
	for _, tc := range []struct{prefix string; want []model.Operation}{
		{"*", []model.Operation{literal}}, {"a", []model.Operation{az}}, {"a/", nil}, {"A", nil}, {"z/\xff", []model.Operation{z}}, {"?", nil},
	} {
		q := query; q.Bytes += uint64(3*len(tc.prefix))
		out, _, err := snapshot.Prefix(ctx, repo, merge.ID, []byte(tc.prefix), q)
		if err != nil || !reflect.DeepEqual(out, tc.want) { t.Fatalf("literal prefix %q: %+v %v", tc.prefix, out, err) }
	}
	// Building an older revision separately cannot mutate the newer snapshot.
	old, _, err := BuildCanonicalPathSnapshot(ctx, repo, root.ID, sources, blobs, budget)
	if err != nil { t.Fatal(err) }
	oldRows, _, err := old.Prefix(ctx, repo, root.ID, []byte("a"), PathPrefixBudget{3,12,3})
	if err != nil || !reflect.DeepEqual(oldRows, []model.Operation{a,az}) { t.Fatal("older snapshot changed") }
	if out, _, err := snapshot.Prefix(ctx, repo, root.ID, nil, query); err != metadata.ErrInvalidArgument || out != nil { t.Fatal("stale source accepted") }
	for _, which := range []string{"paths","bytes","matches"} {
		q := query; switch which { case "paths": q.Paths--; case "bytes": q.Bytes--; case "matches": q.Matches-- }
		if out, _, err := snapshot.Prefix(ctx, repo, merge.ID, nil, q); err != metadata.ErrResourceExhausted || out != nil { t.Fatalf("%s partial result",which) }
	}
	cancel := &pathCancelContext{Context:ctx, stop:3}
	if out, _, err := snapshot.Prefix(cancel, repo, merge.ID, nil, query); err != context.Canceled || out != nil { t.Fatal("partial scan cancellation") }
	for _, which := range []string{"source","entries","path bytes"} {
		short := budget; switch which { case "source": short.Replay.SourceBytes--; case "entries": short.Snapshot.Entries--; case "path bytes": short.Snapshot.PathBytes-- }
		if out, _, err := BuildCanonicalPathSnapshot(ctx,repo,merge.ID,sources,blobs,short); err == nil || out != nil { t.Fatalf("%s build exhaustion",which) }
	}
	bad := append([]derived.TreeSourceFrame(nil), sources...); bad[2].Frame = append([]byte(nil), bad[2].Frame...); bad[2].Frame[len(bad[2].Frame)-1] ^= 1
	if out, _, err := BuildCanonicalPathSnapshot(ctx,repo,left.ID,bad,blobs,budget); err == nil || out != nil { t.Fatal("off-target corruption ignored") }
	if out, _, err := BuildCanonicalPathSnapshot(ctx,[16]byte{9},merge.ID,sources,blobs,budget); err == nil || out != nil { t.Fatal("foreign repository accepted") }
	if out, _, err := BuildCanonicalPathSnapshot(ctx,repo,merge.ID,sources,nil,budget); err == nil || out != nil { t.Fatal("missing blob accepted") }
	unknown := source(model.ChangesetInput{RepoID:repo, Message:[]byte("unknown")})
	if out, used, err := BuildCanonicalPathSnapshot(ctx,repo,unknown.ID,sources,blobs,budget); err != metadata.ErrInvalidArgument || out != nil || used != (PathSnapshotUsage{}) { t.Fatal("unknown selection reached replay") }
	probe := &pathCancelContext{Context:ctx}
	if out, _, err := BuildCanonicalPathSnapshot(probe,repo,merge.ID,sources,blobs,budget); err != nil || out == nil { t.Fatal("probe build failed") }
	late := &pathCancelContext{Context:ctx,stop:probe.calls}
	if out, _, err := BuildCanonicalPathSnapshot(late,repo,merge.ID,sources,blobs,budget); err != context.Canceled || out != nil { t.Fatal("late build cancellation exposed snapshot") }
	for _, invalid := range []PathPrefixBudget{{0,9,3},{3,0,3},{3,9,0},{4097,9,3},{3,64<<20+1,3},{3,9,4097}} {
		if out, _, err := snapshot.Prefix(ctx,repo,merge.ID,nil,invalid); err != metadata.ErrInvalidArgument || out != nil { t.Fatal("invalid query budget accepted") }
	}
	if out, _, err := snapshot.Prefix(ctx,repo,merge.ID,make([]byte,65536),query); err != metadata.ErrInvalidArgument || out != nil { t.Fatal("excessive prefix accepted") }
	zero := &PathSnapshot{}
	if out, _, err := zero.Prefix(ctx,repo,merge.ID,nil,query); err != metadata.ErrInvalidArgument || out != nil { t.Fatal("zero snapshot accepted") }
	if out, _, err := snapshot.Prefix(nil,repo,merge.ID,nil,query); err != metadata.ErrInvalidArgument || out != nil { t.Fatal("nil context accepted") }
	out, _, err = snapshot.Prefix(ctx,repo,merge.ID,nil,query)
	if err != nil || !reflect.DeepEqual(out,want) { t.Fatal("result alias mutated snapshot") }
}
