package search

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

func TestCanonicalContentAdmissionAndLiteralSearch(t *testing.T) {
	ctx := context.Background(); repo := [16]byte{4}
	blobs := make(map[model.BlobID][]byte)
	var rows []model.Operation; var frameBytes uint64
	for i, payload := range [][]byte{nil, []byte("go\n"), []byte("go\n"), {0,'x'}, {0xff}, []byte("large"), []byte("go\n")} {
		id, err := model.HashBlob(ctx,uint64(len(payload)),bytes.NewReader(payload)); if err != nil { t.Fatal(err) }
		var frame bytes.Buffer; if err := model.EncodeBlob(ctx,&frame,uint64(len(payload)),bytes.NewReader(payload)); err != nil { t.Fatal(err) }
		blobs[id] = append([]byte(nil),frame.Bytes()...); frameBytes += uint64(frame.Len())
		path, err := model.NewPath([]byte{byte('a'+i)}); if err != nil { t.Fatal(err) }
		tag := model.SetRegular; if i == 2 { tag = model.SetExecutable }; if i == 6 { tag = model.SetSymlink }
		op, err := model.NewOperation(path,tag,&id); if err != nil { t.Fatal(err) }; rows = append(rows,op)
	}
	change, err := model.NewChangeset(model.ChangesetInput{RepoID:repo,Operations:rows}); if err != nil { t.Fatal(err) }
	id, err := model.HashChangeset(ctx,change); if err != nil { t.Fatal(err) }
	var source bytes.Buffer; if err := model.EncodeChangeset(ctx,&source,change); err != nil { t.Fatal(err) }
	graph := derived.TreeGraphBudget{Visits:4096,PageBytes:4096*derived.MaxTreePageBytes,ContextBytes:64<<20}
	objects := derived.TreeObjectGraphBudget{Graph:graph,BlobBytes:1<<20}
	step := derived.TreeCheckedWriteBudget{Parent:objects,Candidate:objects,Rewrite:derived.TreeChangesetBudget{Rewrite:derived.TreeRewriteBudget{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes,WriteBytes:4096*derived.MaxTreePageBytes},Operations:4096,InputBytes:model.MaxChangesetPayload}}
	paths, _, err := BuildCanonicalPathSnapshot(ctx,repo,id,[]derived.TreeSourceFrame{{ID:id,Frame:source.Bytes()}},blobs,PathSnapshotBudget{Replay:derived.TreeReplayBudget{Sources:1,SourceBytes:uint64(source.Len()),Pages:4096,PageBytes:4096*derived.MaxTreePageBytes,Step:step},Snapshot:derived.TreeEntriesBudget{Graph:graph,Entries:7,PathBytes:14}})
	if err != nil { t.Fatal(err) }
	budget := ContentBudget{Files:7,FrameBytes:frameBytes,FileBytes:3,TextBytes:6}
	snapshot, used, err := BuildContentSnapshot(ctx,paths,blobs,budget)
	if err != nil || used != (ContentUsage{7,frameBytes,6}) { t.Fatalf("admission: %+v %v",used,err) }
	entries := snapshot.Entries()
	classes := []ContentClass{ContentText,ContentText,ContentText,ContentBinary,ContentInvalidUTF8,ContentTooLarge,ContentSymlink}
	if len(entries) != len(classes) { t.Fatal("missing classifications") }
	for i, entry := range entries {
		if entry.Operation != rows[i] || entry.Class != classes[i] { t.Fatalf("entry %d: %+v",i,entry) }
		want := ""; if i == 1 || i == 2 { want = "go\n" }; if entry.Text != want { t.Fatal("excluded/truncated text exposed") }
	}
	query := ContentQueryBudget{Work:12,Matches:2}
	out, work, err := snapshot.Contains(ctx,repo,id,"go",query)
	if err != nil || work != 12 || !reflect.DeepEqual(out,rows[1:3]) { t.Fatalf("literal query: %+v %d %v",out,work,err) }
	for _, q := range []ContentQueryBudget{{11,2},{12,1}} {
		if out, _, err := snapshot.Contains(ctx,repo,id,"go",q); err != metadata.ErrResourceExhausted || out != nil { t.Fatal("query partial result") }
	}
	for _, needle := range []string{"GO","g.*","g o"} {
		if out, _, err := snapshot.Contains(ctx,repo,id,needle,ContentQueryBudget{64<<20,7}); err != nil || len(out) != 0 { t.Fatal("nonliteral match") }
	}
	for _, needle := range []string{"","\x00","\xff"} {
		if out, _, err := snapshot.Contains(ctx,repo,id,needle,query); err != metadata.ErrInvalidArgument || out != nil { t.Fatal("invalid query") }
	}
	for _, which := range []string{"files","frames","text"} {
		short := budget; switch which { case "files": short.Files--; case "frames": short.FrameBytes--; case "text": short.TextBytes-- }
		if out, _, err := BuildContentSnapshot(ctx,paths,blobs,short); err != metadata.ErrResourceExhausted || out != nil { t.Fatalf("%s exhaustion exposed index",which) }
	}
	zero := budget; zero.FileBytes=0; zero.TextBytes=0
	if s, used, err := BuildContentSnapshot(ctx,paths,blobs,zero); err != nil || used.TextBytes != 0 || s.Entries()[0].Class != ContentText || s.Entries()[1].Class != ContentTooLarge { t.Fatal("zero payload policy") }
	bad := make(map[model.BlobID][]byte); for k,v := range blobs { bad[k] = append([]byte(nil),v...) }
	largeID,_ := rows[5].Target(); bad[largeID][len(bad[largeID])-1] ^= 1
	if out, _, err := BuildContentSnapshot(ctx,paths,bad,budget); err == nil || out != nil { t.Fatal("oversized corrupt blob classified instead of rejected") }
	delete(bad,largeID)
	if out, _, err := BuildContentSnapshot(ctx,paths,bad,budget); err != metadata.ErrFailedPrecondition || out != nil { t.Fatal("missing blob classified") }
	probe := &pathCancelContext{Context:ctx}
	if out, _, err := BuildContentSnapshot(probe,paths,blobs,budget); err != nil || out == nil { t.Fatal("probe") }
	if out, _, err := BuildContentSnapshot(&pathCancelContext{Context:ctx,stop:probe.calls},paths,blobs,budget); err != context.Canceled || out != nil { t.Fatal("late admission cancellation") }
	if out, _, err := snapshot.Contains(&pathCancelContext{Context:ctx,stop:4},repo,id,"go",query); err != context.Canceled || out != nil { t.Fatal("query cancellation") }
	if out, _, err := snapshot.Contains(ctx,[16]byte{9},id,"go",query); err != metadata.ErrInvalidArgument || out != nil { t.Fatal("foreign query") }
	if out, _, err := snapshot.Contains(ctx,repo,model.ChangesetID{},"go",query); err != metadata.ErrInvalidArgument || out != nil { t.Fatal("wrong revision query") }
	// A new canonical revision drops b, retains c, changes g from symlink
	// to regular and adds h sharing verified text plus i as a new symlink kind.
	op := func(path string, tag model.OperationTag, blob model.BlobID) model.Operation {
		p, err := model.NewPath([]byte(path)); if err != nil { t.Fatal(err) }
		var target *model.BlobID; if tag != model.Delete { target=&blob }
		v, err := model.NewOperation(p,tag,target); if err != nil { t.Fatal(err) }; return v
	}
	textID,_ := rows[1].Target()
	g := op("g",model.SetRegular,textID); h := op("h",model.SetRegular,textID); i := op("i",model.SetSymlink,largeID)
	child, err := model.NewChangeset(model.ChangesetInput{RepoID:repo,Parents:[]model.ChangesetID{id},Operations:[]model.Operation{op("b",model.Delete,model.BlobID{}),g,h,i}}); if err != nil { t.Fatal(err) }
	childID, err := model.HashChangeset(ctx,child); if err != nil { t.Fatal(err) }
	var childFrame bytes.Buffer; if err := model.EncodeChangeset(ctx,&childFrame,child); err != nil { t.Fatal(err) }
	nextPaths, _, err := BuildCanonicalPathSnapshot(ctx,repo,childID,[]derived.TreeSourceFrame{{ID:id,Frame:source.Bytes()},{ID:childID,Frame:childFrame.Bytes()}},blobs,PathSnapshotBudget{Replay:derived.TreeReplayBudget{Sources:2,SourceBytes:uint64(source.Len()+childFrame.Len()),Pages:4096,PageBytes:4096*derived.MaxTreePageBytes,Step:step},Snapshot:derived.TreeEntriesBudget{Graph:graph,Entries:8,PathBytes:16}})
	if err != nil { t.Fatal(err) }
	reuseBudget := ContentBudget{Files:8,FrameBytes:uint64(len(blobs[largeID])),FileBytes:3,TextBytes:9}
	needed := map[model.BlobID][]byte{largeID:blobs[largeID]}
	next, reused, err := BuildContentSnapshotReusing(ctx,nextPaths,snapshot,needed,reuseBudget)
	if err != nil || reused.Reused != 7 || reused.Admission != (ContentUsage{8,reuseBudget.FrameBytes,9}) { t.Fatalf("reuse: %+v %v",reused,err) }
	got, _, err := next.Contains(ctx,repo,childID,"go",ContentQueryBudget{18,3})
	if err != nil || !reflect.DeepEqual(got,[]model.Operation{rows[2],g,h}) { t.Fatal("reuse resurrected deletion or wrong mode/path") }
	if next.Entries()[7].Class != ContentSymlink { t.Fatal("file classification reused as symlink") }
	freshBudget := reuseBudget; freshBudget.FrameBytes=1<<20
	fresh, _, err := BuildContentSnapshot(ctx,nextPaths,blobs,freshBudget)
	if err != nil || !reflect.DeepEqual(next.Entries(),fresh.Entries()) { t.Fatal("incremental differs from fresh") }
	if failed, _, err := BuildContentSnapshotReusing(ctx,nextPaths,snapshot,nil,reuseBudget); err != metadata.ErrFailedPrecondition || failed != nil { t.Fatal("missing mode-specific content accepted") }
	for _, which := range []string{"files","frames","text"} {
		short:=reuseBudget; switch which { case "files": short.Files--; case "frames": short.FrameBytes--; case "text": short.TextBytes-- }
		if failed, _, err := BuildContentSnapshotReusing(ctx,nextPaths,snapshot,needed,short); err != metadata.ErrResourceExhausted || failed != nil { t.Fatalf("%s reuse partial",which) }
	}
	policy := reuseBudget; policy.FileBytes++
	if failed, _, err := BuildContentSnapshotReusing(ctx,nextPaths,snapshot,blobs,policy); err != metadata.ErrInvalidArgument || failed != nil { t.Fatal("size policy mismatch reused classifications") }
	foreign := *snapshot; foreign.repository=[16]byte{9}
	if failed, _, err := BuildContentSnapshotReusing(ctx,nextPaths,&foreign,blobs,reuseBudget); err != metadata.ErrInvalidArgument || failed != nil { t.Fatal("cross-repository reuse") }
	repeat, repeated, err := BuildContentSnapshotReusing(ctx,nextPaths,next,nil,ContentBudget{8,1,3,9})
	if err != nil || repeated.Reused != 8 || repeated.Admission.FrameBytes != 0 || !reflect.DeepEqual(repeat.Entries(),next.Entries()) { t.Fatal("repeat rebuild not idempotent") }
	// A changed blob at an unchanged path must not reuse the prior text.
	newID, err := model.HashBlob(ctx,3,bytes.NewReader([]byte("new"))); if err != nil { t.Fatal(err) }
	var newFrame bytes.Buffer; if err := model.EncodeBlob(ctx,&newFrame,3,bytes.NewReader([]byte("new"))); err != nil { t.Fatal(err) }
	blobs[newID]=newFrame.Bytes(); replacement:=op("c",model.SetExecutable,newID)
	third, err := model.NewChangeset(model.ChangesetInput{RepoID:repo,Parents:[]model.ChangesetID{childID},Operations:[]model.Operation{replacement}}); if err != nil { t.Fatal(err) }
	thirdID, err := model.HashChangeset(ctx,third); if err != nil { t.Fatal(err) }
	var thirdFrame bytes.Buffer; if err := model.EncodeChangeset(ctx,&thirdFrame,third); err != nil { t.Fatal(err) }
	thirdPaths, _, err := BuildCanonicalPathSnapshot(ctx,repo,thirdID,[]derived.TreeSourceFrame{{ID:id,Frame:source.Bytes()},{ID:childID,Frame:childFrame.Bytes()},{ID:thirdID,Frame:thirdFrame.Bytes()}},blobs,PathSnapshotBudget{Replay:derived.TreeReplayBudget{Sources:3,SourceBytes:uint64(source.Len()+childFrame.Len()+thirdFrame.Len()),Pages:4096,PageBytes:4096*derived.MaxTreePageBytes,Step:step},Snapshot:derived.TreeEntriesBudget{Graph:graph,Entries:8,PathBytes:16}})
	if err != nil { t.Fatal(err) }
	thirdBudget:=ContentBudget{8,uint64(newFrame.Len()),3,9}
	if v, _, err := BuildContentSnapshotReusing(ctx,thirdPaths,next,nil,thirdBudget); err != metadata.ErrFailedPrecondition || v != nil { t.Fatal("same-path changed blob reused stale text") }
	updated, updateUsage, err := BuildContentSnapshotReusing(ctx,thirdPaths,next,map[model.BlobID][]byte{newID:newFrame.Bytes()},thirdBudget)
	if err != nil || updateUsage.Reused != 7 || updateUsage.Admission.FrameBytes != uint64(newFrame.Len()) { t.Fatalf("changed blob admission: %+v %v",updateUsage,err) }
	if got, _, err := updated.Contains(ctx,repo,thirdID,"new",ContentQueryBudget{27,1}); err != nil || !reflect.DeepEqual(got,[]model.Operation{replacement}) { t.Fatal("new text not indexed") }
	owned:=updated.Entries(); owned[1].Text="broken"; owned[1].Operation=rows[0]
	previousOwned:=next.Entries(); previousOwned[1].Text="broken"
	for j:=range newFrame.Bytes() { newFrame.Bytes()[j]=0 }
	if got, _, err := updated.Contains(ctx,repo,thirdID,"new",ContentQueryBudget{27,1}); err != nil || !reflect.DeepEqual(got,[]model.Operation{replacement}) { t.Fatal("new text aliases returned entries or frame bytes") }
	if got, _, err := updated.Contains(ctx,repo,thirdID,"go",ContentQueryBudget{18,2}); err != nil || !reflect.DeepEqual(got,[]model.Operation{g,h}) { t.Fatal("reused snapshot ownership failed") }
	if got, _, err := next.Contains(ctx,repo,childID,"go",ContentQueryBudget{18,3}); err != nil || !reflect.DeepEqual(got,[]model.Operation{rows[2],g,h}) { t.Fatal("prior snapshot mutated by reuse") }
	probeReuse := &pathCancelContext{Context:ctx}
	if v, _, err := BuildContentSnapshotReusing(probeReuse,nextPaths,snapshot,needed,reuseBudget); err != nil || v == nil { t.Fatal("reuse probe") }
	if v, _, err := BuildContentSnapshotReusing(&pathCancelContext{Context:ctx,stop:probeReuse.calls},nextPaths,snapshot,needed,reuseBudget); err != context.Canceled || v != nil { t.Fatal("late reuse cancellation") }
	if v, _, err := BuildContentSnapshotReusing(ctx,nextPaths,nil,blobs,freshBudget); err != nil || !reflect.DeepEqual(v.Entries(),fresh.Entries()) { t.Fatal("nil previous changed fresh semantics") }
	entries[1].Text="mutated"; entries[1].Operation=rows[5]; out[0]=rows[5]
	for _, frame := range blobs { for i := range frame { frame[i]=0 } }
	again, _, err := snapshot.Contains(ctx,repo,id,"go",query)
	if err != nil || !reflect.DeepEqual(again,rows[1:3]) || snapshot.Entries()[1].Text != "go\n" { t.Fatal("snapshot aliases input/output") }
}

// Build through canonical replay so these tests do not manufacture trusted
// PathSnapshot rows. Faults are injected only after this admission succeeds.
func symlinkStagingFixture(t testing.TB, tag model.OperationTag, payload []byte) (*PathSnapshot, map[model.BlobID][]byte, ContentBudget) {
	t.Helper()
	ctx := context.Background()
	blob, err := model.HashBlob(ctx, uint64(len(payload)), bytes.NewReader(payload))
	if err != nil { t.Fatal(err) }
	var frame bytes.Buffer
	if err := model.EncodeBlob(ctx, &frame, uint64(len(payload)), bytes.NewReader(payload)); err != nil { t.Fatal(err) }
	blobs := map[model.BlobID][]byte{blob: frame.Bytes()}
	path, err := model.NewPath([]byte("entry"))
	if err != nil { t.Fatal(err) }
	row, err := model.NewOperation(path, tag, &blob)
	if err != nil { t.Fatal(err) }
	repo := [16]byte{6}
	change, err := model.NewChangeset(model.ChangesetInput{RepoID: repo, Operations: []model.Operation{row}})
	if err != nil { t.Fatal(err) }
	id, err := model.HashChangeset(ctx, change)
	if err != nil { t.Fatal(err) }
	var source bytes.Buffer
	if err := model.EncodeChangeset(ctx, &source, change); err != nil { t.Fatal(err) }
	graph := derived.TreeGraphBudget{Visits: 4096, PageBytes: 4096*derived.MaxTreePageBytes, ContextBytes: 64<<20}
	objects := derived.TreeObjectGraphBudget{Graph: graph, BlobBytes: 1<<20}
	step := derived.TreeCheckedWriteBudget{Parent: objects, Candidate: objects, Rewrite: derived.TreeChangesetBudget{Rewrite: derived.TreeRewriteBudget{Pages: 4096, ReadBytes: 4096*derived.MaxTreePageBytes, WriteBytes: 4096*derived.MaxTreePageBytes}, Operations: 4096, InputBytes: model.MaxChangesetPayload}}
	paths, _, err := BuildCanonicalPathSnapshot(ctx, repo, id, []derived.TreeSourceFrame{{ID: id, Frame: source.Bytes()}}, blobs, PathSnapshotBudget{Replay: derived.TreeReplayBudget{Sources: 1, SourceBytes: uint64(source.Len()), Pages: 4096, PageBytes: 4096*derived.MaxTreePageBytes, Step: step}, Snapshot: derived.TreeEntriesBudget{Graph: graph, Entries: 1, PathBytes: 10}})
	if err != nil { t.Fatal(err) }
	return paths, blobs, ContentBudget{Files: 1, FrameBytes: uint64(frame.Len()), FileBytes: uint64(len(payload)), TextBytes: uint64(len(payload))}
}

func TestContentSymlinkDiscardPreservesClassificationAndReuse(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{name string; payload []byte}{
		{"empty", nil}, {"text", []byte("target/path")}, {"binary", []byte{'x', 0, 'y'}},
		{"invalid-utf8", []byte{0xff}}, {"multiple-chunks", bytes.Repeat([]byte("x"), 65537)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths, blobs, full := symlinkStagingFixture(t, model.SetSymlink, tc.payload)
			for _, limit := range []uint64{0, 1, 32768, 1<<20} {
				budget := full; budget.FileBytes = limit; budget.TextBytes = 0
				snapshot, used, err := BuildContentSnapshot(ctx, paths, blobs, budget)
				wantUsage := ContentUsage{Files: 1, FrameBytes: full.FrameBytes}
				if err != nil || used != wantUsage || snapshot == nil { t.Fatalf("limit %d: %+v %v", limit, used, err) }
				want := []ContentEntry{{Operation: paths.rows[0], Class: ContentSymlink}}
				if !reflect.DeepEqual(snapshot.Entries(), want) { t.Fatalf("limit %d: symlink payload exposed or misclassified", limit) }
				if got, work, err := snapshot.Contains(ctx, paths.repository, paths.source, "x", ContentQueryBudget{Work: 1, Matches: 1}); err != nil || len(got) != 0 || work != 0 { t.Fatal("symlink participated in text search") }
				repeated, reuse, err := BuildContentSnapshotReusing(ctx, paths, snapshot, nil, budget)
				if err != nil || reuse != (ContentReuseUsage{Admission: ContentUsage{Files: 1}, Reused: 1}) || !reflect.DeepEqual(repeated.Entries(), want) { t.Fatalf("repeat: %+v %v", reuse, err) }
			}
		})
	}
	// A zero-retention writer consumes every chunk without retaining a prefix
	// or aliasing the decoder's scratch buffer, including repeated empty writes.
	stage := &contentStage{}
	for _, chunk := range [][]byte{nil, []byte("target"), bytes.Repeat([]byte{0xff}, 32768), nil} {
		if n, err := stage.Write(chunk); err != nil || n != len(chunk) || stage.data != nil { t.Fatal("discard writer retained data or returned short write") }
	}
}

func TestContentSymlinkDiscardStillRejectsInvalidFrames(t *testing.T) {
	ctx := context.Background()
	paths, blobs, budget := symlinkStagingFixture(t, model.SetSymlink, bytes.Repeat([]byte("x"), 65537))
	budget.FileBytes = 1<<20; budget.TextBytes = 0
	id, _ := paths.rows[0].Target()
	frame := blobs[id]
	for _, kind := range []string{"digest", "truncated", "trailing", "header", "length"} {
		t.Run(kind, func(t *testing.T) {
			bad := bytes.Clone(frame)
			switch kind {
			case "digest": bad[len(bad)-1] ^= 1
			case "truncated": bad = bad[:len(bad)-1]
			case "trailing": bad = append(bad, 0)
			case "header": bad[0] ^= 1
			case "length": bad[21] ^= 1
			}
			admitted := budget; admitted.FrameBytes = uint64(len(bad))
			out, used, err := BuildContentSnapshot(ctx, paths, map[model.BlobID][]byte{id: bad}, admitted)
			if err == nil || out != nil || used != (ContentUsage{Files: 1, FrameBytes: uint64(len(bad))}) { t.Fatalf("invalid frame became classification: %+v %v", used, err) }
		})
	}
	if out, used, err := BuildContentSnapshot(ctx, paths, nil, budget); err != metadata.ErrFailedPrecondition || out != nil || used != (ContentUsage{Files: 1}) { t.Fatalf("missing frame: %+v %v", used, err) }
	short := budget; short.FrameBytes--
	if out, used, err := BuildContentSnapshot(ctx, paths, blobs, short); err != metadata.ErrResourceExhausted || out != nil || used != (ContentUsage{Files: 1}) { t.Fatalf("frame admission: %+v %v", used, err) }
	probe := &pathCancelContext{Context: ctx}
	if out, _, err := BuildContentSnapshot(probe, paths, blobs, budget); err != nil || out == nil { t.Fatal("cancellation probe failed") }
	for stop := 1; stop <= probe.calls; stop++ {
		cancel := &pathCancelContext{Context: ctx, stop: stop}
		out, used, err := BuildContentSnapshot(cancel, paths, blobs, budget)
		if err != context.Canceled || out != nil || used.TextBytes != 0 || used.Files > 1 || used.FrameBytes > budget.FrameBytes { t.Fatalf("checkpoint %d: %+v %v", stop, used, err) }
	}
}

func TestContentSymlinkDiscardDoesNotCrossReuseModes(t *testing.T) {
	ctx := context.Background()
	payload := []byte("target")
	linkPaths, blobs, budget := symlinkStagingFixture(t, model.SetSymlink, payload)
	link, _, err := BuildContentSnapshot(ctx, linkPaths, blobs, budget)
	if err != nil { t.Fatal(err) }
	for _, tag := range []model.OperationTag{model.SetRegular, model.SetExecutable} {
		filePaths, _, _ := symlinkStagingFixture(t, tag, payload)
		if out, _, err := BuildContentSnapshotReusing(ctx, filePaths, link, nil, budget); err != metadata.ErrFailedPrecondition || out != nil { t.Fatal("discarded symlink payload reused as file text") }
		file, used, err := BuildContentSnapshotReusing(ctx, filePaths, link, blobs, budget)
		if err != nil || used.Reused != 0 || used.Admission != (ContentUsage{1, budget.FrameBytes, uint64(len(payload))}) { t.Fatalf("file decode: %+v %v", used, err) }
		if got := file.Entries(); len(got) != 1 || got[0].Text != string(payload) || got[0].Class != ContentText || got[0].Operation != filePaths.rows[0] { t.Fatal("regular/executable staging was discarded") }
		if out, _, err := BuildContentSnapshotReusing(ctx, linkPaths, file, nil, budget); err != metadata.ErrFailedPrecondition || out != nil { t.Fatal("file text reused as symlink") }
		zeroText := budget; zeroText.TextBytes = 0
		back, used, err := BuildContentSnapshotReusing(ctx, linkPaths, file, blobs, zeroText)
		if err != nil || used.Reused != 0 || used.Admission != (ContentUsage{Files: 1, FrameBytes: budget.FrameBytes}) || !reflect.DeepEqual(back.Entries(), link.Entries()) { t.Fatalf("symlink decode: %+v %v", used, err) }
	}
}

func BenchmarkContentSymlinkDiscard(b *testing.B) {
	for _, size := range []int{32, 32769, 262144} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			paths, blobs, budget := symlinkStagingFixture(b, model.SetSymlink, bytes.Repeat([]byte("x"), size))
			budget.TextBytes = 0
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				out, used, err := BuildContentSnapshot(context.Background(), paths, blobs, budget)
				if err != nil || out == nil || used != (ContentUsage{Files: 1, FrameBytes: budget.FrameBytes}) { b.Fatal("symlink snapshot failed") }
			}
		})
	}
}
