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

func TestCanonicalTextReplayCombinesTargetAndDeclaredDelta(t *testing.T) {
	ctx := context.Background(); repo := [16]byte{2}; path, _ := model.NewPath([]byte("a"))
	graph := derived.TreeObjectGraphBudget{Graph:derived.TreeGraphBudget{Visits:4096,PageBytes:4096*derived.MaxTreePageBytes,ContextBytes:64<<20},BlobBytes:1<<20}
	step := derived.TreeCheckedWriteBudget{Parent:graph,Candidate:graph,Rewrite:derived.TreeChangesetBudget{Rewrite:derived.TreeRewriteBudget{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes,WriteBytes:4096*derived.MaxTreePageBytes},Operations:4096,InputBytes:model.MaxChangesetPayload}}
	budget := TreeTextFileMergeBudget{Replay:derived.TreeReplayBudget{Sources:3,SourceBytes:1<<20,Pages:4096,PageBytes:4096*derived.MaxTreePageBytes,Step:step},Lookup:[3]derived.TreeLookupBudget{{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes},{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes},{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes}},Text:ThreeWayTextBudget{12,6,8,2}}
	for _, tc := range []struct{ content [3]string; want string; conflict bool }{
		{[3]string{"a\nb\n","A\nb\n","a\nB\n"},"A\nB\n",false},
		{[3]string{"a\nb\n","A\nb\n","Z\nb\n"},"",true},
	} {
		ids, frames := canonicalMergeInputs(t,tc.content)
		blobs := map[model.BlobID][]byte{}; var selected [3]model.ChangesetID; var sources []derived.TreeSourceFrame
		for i := range selected {
			blobs[ids[i]] = frames[i]
			mode := model.SetRegular; if i == 1 { mode = model.SetExecutable }
			op, err := model.NewOperation(path,mode,&ids[i]); if err != nil { t.Fatal(err) }
			change := model.ChangesetInput{RepoID:repo,Operations:[]model.Operation{op}}
			if i != 0 { change.Parents = []model.ChangesetID{selected[0]} }
			v, err := model.NewChangeset(change); if err != nil { t.Fatal(err) }
			selected[i], err = model.HashChangeset(ctx,v); if err != nil { t.Fatal(err) }
			var frame bytes.Buffer; if err := model.EncodeChangeset(ctx,&frame,v); err != nil { t.Fatal(err) }
			sources = append(sources,derived.TreeSourceFrame{ID:selected[i],Frame:frame.Bytes()})
		}
		got, conflict, used, err := PrepareCanonicalTextFileReplay(ctx,repo,selected[1],selected[0],selected[2],path,sources,blobs,budget)
		if err != nil || (conflict != nil) != tc.conflict || used.Replay.Sources != 3 { t.Fatal(got,conflict,used,err) }
		if tc.conflict {
			if got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict.Base != fileFixture(t,model.SetRegular,tc.content[0]) || conflict.Left != fileFixture(t,model.SetRegular,tc.content[2]) || conflict.Right != fileFixture(t,model.SetExecutable,tc.content[1]) { t.Fatal(got,conflict) }
		} else {
			want, err := PrepareFileOperation(ctx,path,fileFixture(t,model.SetExecutable,tc.want),12)
			if err != nil || got.Operation != want.Operation || !bytes.Equal(got.BlobFrame,want.BlobFrame) { t.Fatal(got,want,err) }
		}
		short := budget; short.Text.Cells--
		if got, conflict, _, err := PrepareCanonicalTextFileReplay(ctx,repo,selected[1],selected[0],selected[2],path,sources,blobs,short); err != ErrTextLimit || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
		bad := budget; bad.Text.Cells = 0
		if got, conflict, used, err := PrepareCanonicalTextFileReplay(ctx,repo,selected[1],selected[0],selected[2],path,sources,nil,bad); err != ErrTextLimit || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil || used != (TreeFileMergeUsage{}) { t.Fatal(got,conflict,used,err) }
		corrupt := append([]derived.TreeSourceFrame(nil), sources...)
		corrupt[1].Frame = append([]byte(nil), sources[1].Frame...)
		corrupt[1].Frame[len(corrupt[1].Frame)-1] ^= 1
		for _, check := range []struct {
			name    string
			parent  model.ChangesetID
			sources []derived.TreeSourceFrame
			budget  TreeTextFileMergeBudget
			want    error
		}{
			{"wrong-actual-parent", selected[2], sources, budget, metadata.ErrFailedPrecondition},
			{"text-limit-before-parent-membership", selected[2], sources, bad, ErrTextLimit},
			{"text-limit-before-source-decode", selected[0], corrupt, bad, ErrTextLimit},
		} {
			t.Run(check.name, func(t *testing.T) {
				got, conflict, used, err := PrepareCanonicalTextFileReplay(ctx, repo, selected[1], check.parent, selected[0], path, check.sources, blobs, check.budget)
				if err != check.want || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil || used != (TreeFileMergeUsage{}) {
					t.Fatalf("wanted %v with no output or usage, got operation=%v blob=%v conflict=%v usage=%+v err=%v", check.want, got.Operation, got.BlobFrame, conflict, used, err)
				}
			})
		}
		cancelled,cancel := context.WithCancel(ctx); cancel()
		if got, conflict, _, err := PrepareCanonicalTextFileReplay(cancelled,repo,selected[1],selected[0],selected[2],path,sources,blobs,budget); err != context.Canceled || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
	}
}

func TestCanonicalRootFileReplayHasExplicitEmptyBase(t *testing.T) {
	ctx := context.Background(); repo := [16]byte{3}; path, _ := model.NewPath([]byte("a"))
	ids, frames := canonicalMergeInputs(t,[3]string{"", "b\x00", "c\x00"})
	blobs := map[model.BlobID][]byte{ids[0]:frames[0],ids[1]:frames[1],ids[2]:frames[2]}
	makeSource := func(parents []model.ChangesetID, ops []model.Operation) derived.TreeSourceFrame {
		v, err := model.NewChangeset(model.ChangesetInput{RepoID:repo,Parents:parents,Operations:ops}); if err != nil { t.Fatal(err) }
		id, err := model.HashChangeset(ctx,v); if err != nil { t.Fatal(err) }
		var frame bytes.Buffer; if err := model.EncodeChangeset(ctx,&frame,v); err != nil { t.Fatal(err) }
		return derived.TreeSourceFrame{ID:id,Frame:frame.Bytes()}
	}
	emptyOp, _ := model.NewOperation(path,model.SetExecutable,&ids[0])
	binaryOp, _ := model.NewOperation(path,model.SetRegular,&ids[1])
	otherOp, _ := model.NewOperation(path,model.SetSymlink,&ids[2])
	absent := makeSource(nil,nil)
	empty := makeSource(nil,[]model.Operation{emptyOp})
	binary := makeSource(nil,[]model.Operation{binaryOp})
	other := makeSource(nil,[]model.Operation{otherOp})
	child := makeSource([]model.ChangesetID{absent.ID},[]model.Operation{binaryOp})
	sources := []derived.TreeSourceFrame{absent,empty,binary,other,child}
	graph := derived.TreeObjectGraphBudget{Graph:derived.TreeGraphBudget{Visits:4096,PageBytes:4096*derived.MaxTreePageBytes,ContextBytes:64<<20},BlobBytes:1<<20}
	step := derived.TreeCheckedWriteBudget{Parent:graph,Candidate:graph,Rewrite:derived.TreeChangesetBudget{Rewrite:derived.TreeRewriteBudget{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes,WriteBytes:4096*derived.MaxTreePageBytes},Operations:4096,InputBytes:model.MaxChangesetPayload}}
	budget := TreeFileMergeBudget{Replay:derived.TreeReplayBudget{Sources:5,SourceBytes:1<<20,Pages:4096,PageBytes:4096*derived.MaxTreePageBytes,Step:step},Lookup:[3]derived.TreeLookupBudget{{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes},{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes},{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes}},Payload:4}
	for _, tc := range []struct{change,target model.ChangesetID; want model.Operation; frame []byte}{{binary.ID,absent.ID,binaryOp,frames[1]},{binary.ID,binary.ID,binaryOp,frames[1]},{absent.ID,other.ID,otherOp,frames[2]},{empty.ID,absent.ID,emptyOp,frames[0]}} {
		got, conflict, used, err := PrepareCanonicalRootFileReplay(ctx,repo,tc.change,tc.target,path,sources,blobs,budget)
		if err != nil || conflict != nil || used.Replay.Sources != 5 || got.Operation != tc.want || !bytes.Equal(got.BlobFrame,tc.frame) { t.Fatal(got,conflict,used,err) }
	}
	got, conflict, _, err := PrepareCanonicalRootFileReplay(ctx,repo,binary.ID,other.ID,path,sources,blobs,budget)
	if err != nil || conflict == nil || got.Operation != (model.Operation{}) || got.BlobFrame != nil || !conflict.Base.IsAbsent() || conflict.Left != fileFixture(t,model.SetSymlink,"c\x00") || conflict.Right != fileFixture(t,model.SetRegular,"b\x00") { t.Fatal(got,conflict,err) }
	if got, conflict, _, err := PrepareCanonicalRootFileReplay(ctx,repo,child.ID,absent.ID,path,sources,blobs,budget); err != metadata.ErrFailedPrecondition || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
	if got, conflict, _, err := PrepareCanonicalFileReplay(ctx,repo,binary.ID,model.ChangesetID{},absent.ID,path,sources,blobs,budget); err != ErrFileState || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal("ordinary API inferred root",got,conflict,err) }
	short := budget; short.Payload = 3
	if got, conflict, _, err := PrepareCanonicalRootFileReplay(ctx,repo,binary.ID,other.ID,path,sources,blobs,short); err != ErrFileBudget || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
	short.Payload = 0
	if got, conflict, _, err := PrepareCanonicalRootFileReplay(ctx,repo,empty.ID,absent.ID,path,sources,blobs,short); err != nil || conflict != nil || got.Operation != emptyOp || len(got.BlobFrame) != 22 { t.Fatal(got,conflict,err) }
	bad := append([]derived.TreeSourceFrame(nil),sources...); bad[4].Frame = append([]byte(nil),child.Frame...); bad[4].Frame[len(child.Frame)-1] ^= 1
	if got, conflict, _, err := PrepareCanonicalRootFileReplay(ctx,repo,binary.ID,absent.ID,path,bad,blobs,budget); err == nil || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
	cancelled,cancel := context.WithCancel(ctx); cancel()
	if got, conflict, _, err := PrepareCanonicalRootFileReplay(cancelled,repo,binary.ID,absent.ID,path,sources,blobs,budget); err != context.Canceled || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
}
