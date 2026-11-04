package workspace

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/query"
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
