package edit

import (
	"bytes"
	"context"
	"testing"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

func TestCanonicalFileRevertExplicitParentAndConflict(t *testing.T) {
	ctx := context.Background(); repo := [16]byte{4}; path, _ := model.NewPath([]byte("a"))
	ids, frames := canonicalMergeInputs(t,[3]string{"a\x00","b\x00","c\x00"})
	blobs := map[model.BlobID][]byte{ids[0]:frames[0],ids[1]:frames[1],ids[2]:frames[2]}
	makeSource := func(parents []model.ChangesetID, tag model.OperationTag, blob *model.BlobID) derived.TreeSourceFrame {
		op, err := model.NewOperation(path,tag,blob); if err != nil { t.Fatal(err) }
		v, err := model.NewChangeset(model.ChangesetInput{RepoID:repo,Parents:parents,Operations:[]model.Operation{op}}); if err != nil { t.Fatal(err) }
		id, err := model.HashChangeset(ctx,v); if err != nil { t.Fatal(err) }
		var frame bytes.Buffer; if err := model.EncodeChangeset(ctx,&frame,v); err != nil { t.Fatal(err) }
		return derived.TreeSourceFrame{ID:id,Frame:frame.Bytes()}
	}
	first := makeSource(nil,model.SetRegular,&ids[0])
	second := makeSource(nil,model.SetExecutable,&ids[1])
	merge := makeSource([]model.ChangesetID{first.ID,second.ID},model.SetSymlink,&ids[2])
	deleted := makeSource([]model.ChangesetID{merge.ID},model.Delete,nil)
	added := makeSource([]model.ChangesetID{deleted.ID},model.SetRegular,&ids[0])
	sources := []derived.TreeSourceFrame{first,second,merge,deleted,added}
	graph := derived.TreeObjectGraphBudget{Graph:derived.TreeGraphBudget{Visits:4096,PageBytes:4096*derived.MaxTreePageBytes,ContextBytes:64<<20},BlobBytes:1<<20}
	step := derived.TreeCheckedWriteBudget{Parent:graph,Candidate:graph,Rewrite:derived.TreeChangesetBudget{Rewrite:derived.TreeRewriteBudget{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes,WriteBytes:4096*derived.MaxTreePageBytes},Operations:4096,InputBytes:model.MaxChangesetPayload}}
	budget := TreeFileMergeBudget{Replay:derived.TreeReplayBudget{Sources:5,SourceBytes:1<<20,Pages:4096,PageBytes:4096*derived.MaxTreePageBytes,Step:step},Lookup:[3]derived.TreeLookupBudget{{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes},{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes},{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes}},Payload:6}
	for i, parent := range []model.ChangesetID{first.ID,second.ID} {
		got, conflict, used, err := PrepareCanonicalFileRevert(ctx,repo,merge.ID,parent,merge.ID,path,sources,blobs,budget)
		if err != nil || conflict != nil || used.Replay.Sources != 5 { t.Fatal(got,conflict,used,err) }
		id, ok := got.Operation.Target(); wantMode := model.SetRegular; if i == 1 { wantMode = model.SetExecutable }
		if !ok || id != ids[i] || got.Operation.Tag() != wantMode || got.Operation.Path() != path || !bytes.Equal(got.BlobFrame,frames[i]) { t.Fatal("wrong explicit merge mainline",got) }
	}
	// Reverting a deletion restores exact binary symlink bytes and mode.
	got, conflict, _, err := PrepareCanonicalFileRevert(ctx,repo,deleted.ID,merge.ID,deleted.ID,path,sources,blobs,budget)
	if err != nil || conflict != nil || got.Operation.Tag() != model.SetSymlink || !bytes.Equal(got.BlobFrame,frames[2]) { t.Fatal(got,conflict,err) }
	// Reverting a later addition creates a DELETE, not an empty SET frame.
	got, conflict, _, err = PrepareCanonicalFileRevert(ctx,repo,added.ID,deleted.ID,added.ID,path,sources,blobs,budget)
	if err != nil || conflict != nil || got.Operation.Tag() != model.Delete || got.Operation.Path() != path || got.BlobFrame != nil { t.Fatal(got,conflict,err) }
	// Concurrent target deletion cannot be silently overwritten by inverse bytes.
	got, conflict, _, err = PrepareCanonicalFileRevert(ctx,repo,merge.ID,first.ID,deleted.ID,path,sources,blobs,budget)
	if err != nil || conflict == nil || got.Operation != (model.Operation{}) || got.BlobFrame != nil { t.Fatal(got,conflict,err) }
	if conflict.Base != fileFixture(t,model.SetSymlink,"c\x00") || !conflict.Left.IsAbsent() || conflict.Right != fileFixture(t,model.SetRegular,"a\x00") { t.Fatal(conflict) }
	for _, tc := range []struct{change,parent model.ChangesetID; want error}{{merge.ID,model.ChangesetID{},ErrFileState},{merge.ID,deleted.ID,metadata.ErrFailedPrecondition},{first.ID,second.ID,metadata.ErrFailedPrecondition}} {
		got, conflict, _, err := PrepareCanonicalFileRevert(ctx,repo,tc.change,tc.parent,merge.ID,path,sources,blobs,budget)
		if err != tc.want || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
	}
	bad := append([]derived.TreeSourceFrame(nil),sources...); bad[3].Frame = append([]byte(nil),deleted.Frame...); bad[3].Frame[len(deleted.Frame)-1] ^= 1
	if got, conflict, _, err := PrepareCanonicalFileRevert(ctx,repo,merge.ID,first.ID,merge.ID,path,bad,blobs,budget); err == nil || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
	short := budget; short.Payload = 5
	if got, conflict, _, err := PrepareCanonicalFileRevert(ctx,repo,merge.ID,first.ID,merge.ID,path,sources,blobs,short); err != ErrFileBudget || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
	short = budget; short.Replay.SourceBytes = 1
	// Corrupt the matching change as well: source admission must win before
	// any decode. The old decode-first implementation returns a digest error.
	admissionBad := append([]derived.TreeSourceFrame(nil),sources...)
	admissionBad[2].Frame = append([]byte(nil),merge.Frame...); admissionBad[2].Frame[len(merge.Frame)-1] ^= 1
	if got, conflict, used, err := PrepareCanonicalFileRevert(ctx,repo,merge.ID,first.ID,merge.ID,path,admissionBad,blobs,short); err != metadata.ErrResourceExhausted || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil || used != (TreeFileMergeUsage{}) { t.Fatal(got,conflict,used,err) }
	if got, conflict, used, err := PrepareCanonicalFileRevert(ctx,repo,merge.ID,first.ID,merge.ID,path,sources,blobs,short); err != metadata.ErrResourceExhausted || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil || used != (TreeFileMergeUsage{}) { t.Fatal(got,conflict,used,err) }
	cancelled,cancel := context.WithCancel(ctx); cancel()
	if got, conflict, _, err := PrepareCanonicalFileRevert(cancelled,repo,merge.ID,first.ID,merge.ID,path,sources,blobs,budget); err != context.Canceled || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
}

func TestCanonicalTextRevertPreservesDisjointTargetEdit(t *testing.T) {
	ctx := context.Background(); repo := [16]byte{8}; path, _ := model.NewPath([]byte("a"))
	graph := derived.TreeObjectGraphBudget{Graph:derived.TreeGraphBudget{Visits:4096,PageBytes:4096*derived.MaxTreePageBytes,ContextBytes:64<<20},BlobBytes:1<<20}
	step := derived.TreeCheckedWriteBudget{Parent:graph,Candidate:graph,Rewrite:derived.TreeChangesetBudget{Rewrite:derived.TreeRewriteBudget{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes,WriteBytes:4096*derived.MaxTreePageBytes},Operations:4096,InputBytes:model.MaxChangesetPayload}}
	budget := TreeTextFileMergeBudget{Replay:derived.TreeReplayBudget{Sources:3,SourceBytes:1<<20,Pages:4096,PageBytes:4096*derived.MaxTreePageBytes,Step:step},Lookup:[3]derived.TreeLookupBudget{{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes},{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes},{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes}},Text:ThreeWayTextBudget{12,6,8,2}}
	for _, tc := range []struct{ target, want string; conflict bool }{{"A\nB\n","a\nB\n",false},{"Z\nb\n","",true}} {
		content := [3]string{"a\nb\n","A\nb\n",tc.target}
		ids, frames := canonicalMergeInputs(t,content)
		blobs := map[model.BlobID][]byte{}; var selected [3]model.ChangesetID; var sources []derived.TreeSourceFrame
		for i := range selected {
			blobs[ids[i]] = frames[i]
			mode := model.SetExecutable; if i == 0 { mode = model.SetRegular }
			op, err := model.NewOperation(path,mode,&ids[i]); if err != nil { t.Fatal(err) }
			input := model.ChangesetInput{RepoID:repo,Operations:[]model.Operation{op}}
			if i != 0 { input.Parents = []model.ChangesetID{selected[i-1]} }
			value, err := model.NewChangeset(input); if err != nil { t.Fatal(err) }
			selected[i], err = model.HashChangeset(ctx,value); if err != nil { t.Fatal(err) }
			var frame bytes.Buffer; if err := model.EncodeChangeset(ctx,&frame,value); err != nil { t.Fatal(err) }
			sources = append(sources,derived.TreeSourceFrame{ID:selected[i],Frame:frame.Bytes()})
		}
		got, conflict, used, err := PrepareCanonicalTextFileRevert(ctx,repo,selected[1],selected[0],selected[2],path,sources,blobs,budget)
		if err != nil || (conflict != nil) != tc.conflict || used.Replay.Sources != 3 { t.Fatal(got,conflict,used,err) }
		if tc.conflict {
			if got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict.Base != fileFixture(t,model.SetExecutable,content[1]) || conflict.Left != fileFixture(t,model.SetExecutable,content[2]) || conflict.Right != fileFixture(t,model.SetRegular,content[0]) { t.Fatal(got,conflict) }
		} else {
			want, err := PrepareFileOperation(ctx,path,fileFixture(t,model.SetRegular,tc.want),12)
			if err != nil || got.Operation != want.Operation || !bytes.Equal(got.BlobFrame,want.BlobFrame) { t.Fatal(got,want,err) }
		}
		short := budget; short.Text.Cells--
		if got, conflict, _, err := PrepareCanonicalTextFileRevert(ctx,repo,selected[1],selected[0],selected[2],path,sources,blobs,short); err != ErrTextLimit || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
		bad := budget; bad.Text.Cells = 0
		if got, conflict, used, err := PrepareCanonicalTextFileRevert(ctx,repo,selected[1],selected[0],selected[2],path,sources,nil,bad); err != ErrTextLimit || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil || used != (TreeFileMergeUsage{}) { t.Fatal(got,conflict,used,err) }
		// Invalid text admission must precede even the extra parent decode.
		badChange := append([]derived.TreeSourceFrame(nil),sources...)
		badChange[1].Frame = append([]byte(nil),sources[1].Frame...); badChange[1].Frame[len(badChange[1].Frame)-1] ^= 1
		if got, conflict, used, err := PrepareCanonicalTextFileRevert(ctx,repo,selected[1],selected[0],selected[2],path,badChange,blobs,bad); err != ErrTextLimit || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil || used != (TreeFileMergeUsage{}) { t.Fatal(got,conflict,used,err) }
		for _, parent := range []model.ChangesetID{model.ChangesetID{},selected[2]} {
			if got, conflict, _, err := PrepareCanonicalTextFileRevert(ctx,repo,selected[1],parent,selected[2],path,sources,blobs,budget); err == nil || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
		}
		corrupt := append([]derived.TreeSourceFrame(nil),sources...); corrupt[2].Frame = append([]byte(nil),sources[2].Frame...); corrupt[2].Frame[len(corrupt[2].Frame)-1] ^= 1
		if got, conflict, _, err := PrepareCanonicalTextFileRevert(ctx,repo,selected[1],selected[0],selected[2],path,corrupt,blobs,budget); err == nil || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
		cancelled,cancel := context.WithCancel(ctx); cancel()
		if got, conflict, _, err := PrepareCanonicalTextFileRevert(cancelled,repo,selected[1],selected[0],selected[2],path,sources,blobs,budget); err != context.Canceled || got.Operation != (model.Operation{}) || got.BlobFrame != nil || conflict != nil { t.Fatal(got,conflict,err) }
	}
}
