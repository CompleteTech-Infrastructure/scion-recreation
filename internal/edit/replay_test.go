package edit

import (
	"bytes"
	"context"
	"testing"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

func TestCanonicalFileReplayPreservesDeclaredDelta(t *testing.T) {
	ctx := context.Background(); repo := [16]byte{5}; path, _ := model.NewPath([]byte("a"))
	ids, frames := canonicalMergeInputs(t,[3]string{"a\x00","b\x00","c\x00"})
	blobs := map[model.BlobID][]byte{ids[0]:frames[0],ids[1]:frames[1],ids[2]:frames[2]}
	makeSource := func(parents []model.ChangesetID, ops []model.Operation) derived.TreeSourceFrame {
		v, err := model.NewChangeset(model.ChangesetInput{RepoID:repo,Parents:parents,Operations:ops}); if err != nil { t.Fatal(err) }
		id, err := model.HashChangeset(ctx,v); if err != nil { t.Fatal(err) }
		var frame bytes.Buffer; if err := model.EncodeChangeset(ctx,&frame,v); err != nil { t.Fatal(err) }
		return derived.TreeSourceFrame{ID:id,Frame:frame.Bytes()}
	}
	regular, _ := model.NewOperation(path,model.SetRegular,&ids[0])
	executable, _ := model.NewOperation(path,model.SetExecutable,&ids[1])
	symlink, _ := model.NewOperation(path,model.SetSymlink,&ids[2])
	remove, _ := model.NewOperation(path,model.Delete,nil)
	base := makeSource(nil,[]model.Operation{regular})
	change := makeSource([]model.ChangesetID{base.ID},[]model.Operation{executable})
	other := makeSource(nil,[]model.Operation{symlink})
	unchanged := makeSource([]model.ChangesetID{base.ID},nil)
	deleted := makeSource([]model.ChangesetID{change.ID},[]model.Operation{remove})
	added := makeSource([]model.ChangesetID{deleted.ID},[]model.Operation{regular})
	sources := []derived.TreeSourceFrame{base,change,other,unchanged,deleted,added}
	graph := derived.TreeObjectGraphBudget{Graph:derived.TreeGraphBudget{Visits:4096,PageBytes:4096*derived.MaxTreePageBytes,ContextBytes:64<<20},BlobBytes:1<<20}
	step := derived.TreeCheckedWriteBudget{Parent:graph,Candidate:graph,Rewrite:derived.TreeChangesetBudget{Rewrite:derived.TreeRewriteBudget{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes,WriteBytes:4096*derived.MaxTreePageBytes},Operations:4096,InputBytes:model.MaxChangesetPayload}}
	budget := TreeFileMergeBudget{Replay:derived.TreeReplayBudget{Sources:6,SourceBytes:1<<20,Pages:4096,PageBytes:4096*derived.MaxTreePageBytes,Step:step},Lookup:[3]derived.TreeLookupBudget{{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes},{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes},{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes}},Payload:6}
	for _, tc := range []struct{change,parent,target model.ChangesetID; op model.Operation; frame []byte}{
		{change.ID,base.ID,base.ID,executable,frames[1]},
		{change.ID,base.ID,change.ID,executable,frames[1]},
		{unchanged.ID,base.ID,other.ID,symlink,frames[2]},
		{deleted.ID,change.ID,change.ID,remove,nil},
		{added.ID,deleted.ID,deleted.ID,regular,frames[0]},
	} {
		got, conflict, used, err := PrepareCanonicalFileReplay(ctx,repo,tc.change,tc.parent,tc.target,path,sources,blobs,budget)
		if err != nil || conflict != nil || got.Operation != tc.op || !bytes.Equal(got.BlobFrame,tc.frame) || used.Replay.Sources != 6 { t.Fatal(got,conflict,used,err) }
		if tc.frame == nil && got.BlobFrame != nil { t.Fatal("DELETE retained a frame") }
	}
	got, conflict, _, err := PrepareCanonicalFileReplay(ctx,repo,change.ID,base.ID,other.ID,path,sources,blobs,budget)
	if err != nil || conflict == nil || got.Operation != (model.Operation{}) || got.BlobFrame != nil { t.Fatal(got,conflict,err) }
	if conflict.Base != fileFixture(t,model.SetRegular,"a\x00") || conflict.Left != fileFixture(t,model.SetSymlink,"c\x00") || conflict.Right != fileFixture(t,model.SetExecutable,"b\x00") { t.Fatal(conflict) }
	if got, conflict, _, err := PrepareCanonicalFileReplay(ctx,repo,change.ID,other.ID,base.ID,path,sources,blobs,budget); err != metadata.ErrFailedPrecondition || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
	duplicate := append(append([]derived.TreeSourceFrame(nil),sources...),change); large := budget; large.Replay.Sources++
	if got, conflict, _, err := PrepareCanonicalFileReplay(ctx,repo,change.ID,base.ID,base.ID,path,duplicate,blobs,large); err != metadata.ErrInvalidArgument || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
	bad := append([]derived.TreeSourceFrame(nil),sources...); bad[1].Frame = append([]byte(nil),change.Frame...); bad[1].Frame[len(change.Frame)-1] ^= 1
	short := budget; short.Replay.SourceBytes = 1
	if got, conflict, used, err := PrepareCanonicalFileReplay(ctx,repo,change.ID,base.ID,base.ID,path,bad,blobs,short); err != metadata.ErrResourceExhausted || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil || used != (TreeFileMergeUsage{}) { t.Fatal(got,conflict,used,err) }
	if got, conflict, _, err := PrepareCanonicalFileReplay(ctx,repo,change.ID,base.ID,base.ID,path,bad,blobs,budget); err == nil || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
	cancelled,cancel := context.WithCancel(ctx); cancel()
	if got, conflict, _, err := PrepareCanonicalFileReplay(cancelled,repo,change.ID,base.ID,base.ID,path,sources,blobs,budget); err != context.Canceled || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
}
