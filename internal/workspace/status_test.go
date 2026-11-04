package workspace

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/query"
	storage "canopy.local/canopy/internal/storage/metadata"
)

func statusFile(t *testing.T, path string, tag model.OperationTag, data []byte) ObservedFile {
	t.Helper()
	return ObservedFile{testPath(t, []byte(path)), tag, append([]byte(nil), data...)}
}
func statusBase(t *testing.T, files []ObservedFile) []model.Operation {
	t.Helper()
	var out []model.Operation
	for _, file := range files {
		id, err := model.HashBlob(context.Background(), uint64(len(file.Payload)), bytes.NewReader(file.Payload))
		if err != nil { t.Fatal(err) }
		op, err := model.NewOperation(file.Path, file.Tag, &id)
		if err != nil { t.Fatal(err) }
		out = append(out, op)
	}
	return out
}
func statusBudget() StatusBudget { return StatusBudget{8192, 64<<20, 64<<20, 8192} }

func TestStatusSnapshotExactBytesModesDeletion(t *testing.T) {
	source := testChangeset(t, "status")
	binding := Manifest{Base: source, SparseVersion: 1, SparseAll: true, State: Clean}
	old := []ObservedFile{
		statusFile(t,"a",model.SetRegular,[]byte{'x',0,0xff}),
		statusFile(t,"b",model.SetRegular,[]byte("same")),
		statusFile(t,"c",model.SetRegular,[]byte("deleted")),
		statusFile(t,"d",model.SetSymlink,[]byte("../outside")),
		statusFile(t,"e",model.SetRegular,nil),
	}
	next := []ObservedFile{old[0], old[1], old[3], old[4], statusFile(t,"f",model.SetRegular,nil)}
	next[1].Tag = model.SetExecutable
	next[2] = statusFile(t,"d",model.SetSymlink,[]byte("../other"))
	base := statusBase(t, old)
	for _, state := range []DirtyState{Clean, Dirty, Uncertain} {
		binding.State = state
		binding.DirtyPaths = []model.Path{testPath(t, []byte("unrelated-hint"))}
		got, err := CompareStatusSnapshot(context.Background(),binding,source,base,next,statusBudget())
		if err != nil || len(got) != 4 { t.Fatalf("state %v: %v %v",state,got,err) }
		if string(got[0].Path.Bytes()) != "b" || !got[0].ModeChanged || got[0].ContentChanged || got[0].Before != base[1] { t.Fatal("mode-only change") }
		if string(got[1].Path.Bytes()) != "c" || !got[1].BeforePresent || got[1].AfterPresent { t.Fatal("deletion") }
		if string(got[2].Path.Bytes()) != "d" || !got[2].ContentChanged || got[2].ModeChanged { t.Fatal("opaque symlink content") }
		if string(got[3].Path.Bytes()) != "f" || got[3].BeforePresent || !got[3].AfterPresent { t.Fatal("empty addition") }
		got[0].Before = model.Operation{}
		if base[1].Path() != old[1].Path { t.Fatal("result aliases base") }
	}
}

func TestStatusSnapshotSparseAndExactBudgets(t *testing.T) {
	source := testChangeset(t,"sparse-status")
	binding := Manifest{Base:source,SparseVersion:1,Sparse:[]model.Path{testPath(t,[]byte("a"))}}
	base := statusBase(t,[]ObservedFile{statusFile(t,"a/x",model.SetRegular,[]byte("old")),statusFile(t,"ab",model.SetRegular,nil)})
	next := []ObservedFile{statusFile(t,"a/x",model.SetRegular,[]byte("new")),statusFile(t,"ab",model.SetRegular,bytes.Repeat([]byte{'z'},100))}
	budget := StatusBudget{4,10,3,1}
	got,err := CompareStatusSnapshot(context.Background(),binding,source,base,next,budget)
	if err != nil || len(got)!=1 || string(got[0].Path.Bytes())!="a/x" { t.Fatal(got,err) }
	for _, short := range []StatusBudget{{3,10,3,1},{4,9,3,1},{4,10,2,1}} {
		if out,err:=CompareStatusSnapshot(context.Background(),binding,source,base,next,short);err!=ErrStatusLimit||out!=nil { t.Fatal("insufficient budget",out,err) }
	}
	binding.Sparse=nil // Select nothing; not the implicit root.
	if out,err:=CompareStatusSnapshot(context.Background(),binding,source,base,next,StatusBudget{4,10,1,1});err!=nil||len(out)!=0 { t.Fatal(out,err) }
}

type statusCancelContext struct { context.Context; calls, stop int }
func (c *statusCancelContext) Err() error { c.calls++; if c.calls>=c.stop{return context.Canceled};return nil }

func TestStatusSnapshotRejectsFileAncestorsBeforeSelection(t *testing.T) {
	source:=testChangeset(t,"status-shape")
	// The lexically intervening sibling catches adjacent-only prefix checks.
	invalid:=[]ObservedFile{statusFile(t,"a",model.SetRegular,nil),statusFile(t,"a-",model.SetRegular,nil),statusFile(t,"a/b",model.SetRegular,nil)}
	for _, all:=range []bool{true,false} {
		binding:=Manifest{Base:source,SparseVersion:1,SparseAll:all}
		if !all { binding.Sparse=[]model.Path{testPath(t,[]byte("unrelated"))} }
		for _, fromBase:=range []bool{true,false} {
			var base []model.Operation
			var observed []ObservedFile
			if fromBase { base=statusBase(t,invalid) } else { observed=invalid }
			out,err:=CompareStatusSnapshot(context.Background(),binding,source,base,observed,statusBudget())
			if err!=ErrStatusInput||out!=nil { t.Fatalf("all=%v base=%v: %v %v",all,fromBase,out,err) }
		}
	}
	// Component boundaries matter; a sibling with a byte prefix is legal,
	// and equal paths on opposite sides do not conflict with each other.
	valid:=invalid[:2]
	binding:=Manifest{Base:source,SparseVersion:1,SparseAll:true}
	if out,err:=CompareStatusSnapshot(context.Background(),binding,source,statusBase(t,valid),valid,statusBudget());err!=nil||len(out)!=0 { t.Fatal(out,err) }
}

func TestStatusSnapshotRejectsAndCancelsWithoutPartialOutput(t *testing.T) {
	source:=testChangeset(t,"status-errors")
	binding:=Manifest{Base:source,SparseVersion:1,SparseAll:true}
	files:=[]ObservedFile{statusFile(t,"a",model.SetRegular,[]byte("one")),statusFile(t,"b",model.SetRegular,[]byte("two"))}
	saved:=[]ObservedFile{statusFile(t,"a",model.SetRegular,[]byte("one")),statusFile(t,"b",model.SetRegular,[]byte("two"))}
	for _, invalid:=range [][]ObservedFile{{files[1],files[0]},{files[0],files[0]},{{Path:files[0].Path,Tag:model.Delete}},{{Tag:model.SetRegular}}} {
		if out,err:=CompareStatusSnapshot(context.Background(),binding,source,nil,invalid,statusBudget());err!=ErrStatusInput||out!=nil{t.Fatal(out,err)}
	}
	if out,err:=CompareStatusSnapshot(context.Background(),binding,testChangeset(t,"other"),nil,files,statusBudget());err!=ErrStatusInput||out!=nil{t.Fatal(out,err)}
	if out,err:=CompareStatusSnapshot(nil,binding,source,nil,files,statusBudget());err!=ErrStatusInput||out!=nil{t.Fatal(out,err)}
	short:=statusBudget();short.Changes=1
	if out,err:=CompareStatusSnapshot(context.Background(),binding,source,nil,files,short);err!=query.ErrFileDiffLimit||out!=nil{t.Fatal("partial changes escaped",out,err)}
	// Exercise cancellation at every check through hashing and comparison,
	// including after earlier rows/deltas have been privately accumulated.
	probe:=&statusCancelContext{Context:context.Background(),stop:1000000}
	if out,err:=CompareStatusSnapshot(probe,binding,source,nil,files,statusBudget());err!=nil||len(out)!=2{t.Fatal(out,err)}
	for stop:=1;stop<=probe.calls;stop++ {
		ctx:=&statusCancelContext{Context:context.Background(),stop:stop}
		if out,err:=CompareStatusSnapshot(ctx,binding,source,nil,files,statusBudget());err!=context.Canceled||out!=nil{t.Fatalf("stop %d: %v %v",stop,out,err)}
	}
	if !reflect.DeepEqual(files,saved){t.Fatal("input bytes mutated")}
}

func TestCanonicalStatusBindsBaseAndVerifiesCompleteDAG(t *testing.T) {
	ctx:=context.Background();repo:=[16]byte{9}
	files:=[]ObservedFile{statusFile(t,"a",model.SetRegular,[]byte("payload")),statusFile(t,"b",model.SetRegular,[]byte("payload"))}
	rows:=statusBase(t,files);blob,_:=rows[0].Target()
	var raw bytes.Buffer
	if err:=model.EncodeBlob(ctx,&raw,7,bytes.NewReader([]byte("payload")));err!=nil{t.Fatal(err)}
	blobs:=map[model.BlobID][]byte{blob:raw.Bytes()}
	source:=func(input model.ChangesetInput) derived.TreeSourceFrame {
		v,err:=model.NewChangeset(input);if err!=nil{t.Fatal(err)}
		id,err:=model.HashChangeset(ctx,v);if err!=nil{t.Fatal(err)}
		var frame bytes.Buffer;if err:=model.EncodeChangeset(ctx,&frame,v);err!=nil{t.Fatal(err)}
		return derived.TreeSourceFrame{ID:id,Frame:frame.Bytes()}
	}
	root:=source(model.ChangesetInput{RepoID:repo,Operations:rows[:1]})
	left:=source(model.ChangesetInput{RepoID:repo,Parents:[]model.ChangesetID{root.ID},Operations:rows[1:]})
	del,err:=model.NewOperation(files[0].Path,model.Delete,nil);if err!=nil{t.Fatal(err)}
	right:=source(model.ChangesetInput{RepoID:repo,Parents:[]model.ChangesetID{root.ID},Operations:[]model.Operation{del}})
	merge:=source(model.ChangesetInput{RepoID:repo,Parents:[]model.ChangesetID{left.ID,right.ID}})
	sources:=[]derived.TreeSourceFrame{root,left,right,merge}
	graph:=derived.TreeGraphBudget{Visits:4096,PageBytes:4096*derived.MaxTreePageBytes,ContextBytes:64<<20}
	objects:=derived.TreeObjectGraphBudget{Graph:graph,BlobBytes:1<<20}
	step:=derived.TreeCheckedWriteBudget{Parent:objects,Candidate:objects,Rewrite:derived.TreeChangesetBudget{Rewrite:derived.TreeRewriteBudget{Pages:4096,ReadBytes:4096*derived.MaxTreePageBytes,WriteBytes:4096*derived.MaxTreePageBytes},Operations:4096,InputBytes:model.MaxChangesetPayload}}
	budget:=CanonicalStatusBudget{Replay:derived.TreeReplayBudget{Sources:4,SourceBytes:model.MaxChangesetPayload+88,Pages:4096,PageBytes:4096*derived.MaxTreePageBytes,Step:step},Snapshot:derived.TreeEntriesBudget{Graph:graph,Entries:2,PathBytes:4},Compare:statusBudget()}
	binding:=Manifest{Base:merge.ID,SparseVersion:1,SparseAll:true,State:Uncertain}
	observed:=[]ObservedFile{files[0],files[1],statusFile(t,"c",model.SetRegular,nil)};observed[1].Tag=model.SetExecutable
	got,used,err:=CompareCanonicalStatus(ctx,repo,binding,sources,blobs,observed,budget)
	want,err2:=CompareStatusSnapshot(ctx,binding,merge.ID,rows,observed,budget.Compare)
	if err!=nil||err2!=nil||!reflect.DeepEqual(got,want)||len(got)!=2||used.Replay.Sources!=4||used.Snapshot.Visits==0{t.Fatal(got,used,err,err2)}
	// Select a non-final source: right deleted a; parent one must not be
	// unioned into merge's first-parent tree or ignored during verification.
	binding.Base=right.ID
	if out,_,err:=CompareCanonicalStatus(ctx,repo,binding,sources,blobs,files[:1],budget);err!=nil||len(out)!=1||out[0].BeforePresent{t.Fatal(out,err)}
	binding.Base=left.ID
	bad:=append([]derived.TreeSourceFrame(nil),sources...);bad[3].Frame=append([]byte(nil),merge.Frame...);bad[3].Frame[len(bad[3].Frame)-1]^=1
	if out,_,err:=CompareCanonicalStatus(ctx,repo,binding,bad,blobs,files,budget);err==nil||out!=nil{t.Fatal("later corruption ignored")}
	binding.Base=merge.ID
	if out,_,err:=CompareCanonicalStatus(ctx,repo,binding,[]derived.TreeSourceFrame{root,left,merge},blobs,files,budget);err==nil||out!=nil{t.Fatal("missing second parent ignored")}
	if out,_,err:=CompareCanonicalStatus(ctx,[16]byte{10},binding,sources,blobs,files,budget);err==nil||out!=nil{t.Fatal("wrong repository")}
	if out,_,err:=CompareCanonicalStatus(ctx,repo,binding,sources,nil,files,budget);err==nil||out!=nil{t.Fatal("missing canonical blob")}
	binding.Base=testChangeset(t,"missing-status-base")
	if out,usage,err:=CompareCanonicalStatus(ctx,repo,binding,sources,blobs,files,budget);err!=storage.ErrNotFound||out!=nil||usage.Replay.Sources!=4{t.Fatal(out,usage,err)}
	binding.Base=merge.ID;short:=budget;short.Snapshot.PathBytes=3
	if out,_,err:=CompareCanonicalStatus(ctx,repo,binding,sources,blobs,files,short);err==nil||out!=nil{t.Fatal("enumeration budget ignored")}
	short=budget;short.Compare.Entries=3;short.Compare.Changes=3
	if out,usage,err:=CompareCanonicalStatus(ctx,repo,binding,sources,blobs,files,short);err!=ErrStatusLimit||out!=nil||usage.Replay!=used.Replay||usage.Snapshot!=used.Snapshot{t.Fatal("combined row exhaustion must follow replay/enumeration",out,usage,err)}
	probe:=&statusCancelContext{Context:ctx,stop:1000000}
	if out,_,err:=CompareCanonicalStatus(probe,repo,binding,sources,blobs,observed,budget);err!=nil||len(out)!=2{t.Fatal(out,err)}
	late:=&statusCancelContext{Context:ctx,stop:probe.calls}
	if out,_,err:=CompareCanonicalStatus(late,repo,binding,sources,blobs,observed,budget);err!=context.Canceled||out!=nil{t.Fatal("late cancellation",out,err)}
}
