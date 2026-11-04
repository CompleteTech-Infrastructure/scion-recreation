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
	entries[1].Text="mutated"; entries[1].Operation=rows[5]; out[0]=rows[5]
	for _, frame := range blobs { for i := range frame { frame[i]=0 } }
	again, _, err := snapshot.Contains(ctx,repo,id,"go",query)
	if err != nil || !reflect.DeepEqual(again,rows[1:3]) || snapshot.Entries()[1].Text != "go\n" { t.Fatal("snapshot aliases input/output") }
}
