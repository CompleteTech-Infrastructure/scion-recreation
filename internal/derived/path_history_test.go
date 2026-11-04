package derived

import (
	"context"
	"testing"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

func TestDerivePathHistoryStepFirstParentTransitions(t *testing.T) {
	empty, emptyRoot, _ := EncodeTreePageAt(UnlinkedTreePage{}, nil, nil)
	frames := map[TreePageID][]byte{emptyRoot: empty}
	path, _ := model.NewPath([]byte("file"))
	missing, _ := model.NewPath([]byte("other"))
	tid, _ := model.NewTypedID(model.BlobKind, [32]byte{1}); blob, _ := model.NewBlobID(tid)
	otherTID, _ := model.NewTypedID(model.BlobKind, [32]byte{2}); otherBlob, _ := model.NewBlobID(otherTID)
	budget := PathHistoryBudget{model.MaxChangesetPayload, TreeLookupBudget{4096, 4096*MaxTreePageBytes}}
	rewrite := TreeChangesetBudget{TreeRewriteBudget{4096, 4096*MaxTreePageBytes, 4096*MaxTreePageBytes}, 4096, model.MaxChangesetPayload}
	var parent *metadata.DerivedResult
	var lastSource model.Changeset
	var expectedBefore model.Operation
	var lastCurrent, lastParent metadata.DerivedResult
	for i, tc := range []struct { tag model.OperationTag; target *model.BlobID; changed, before, after bool }{
		{model.SetRegular, &blob, true, false, true},
		{model.SetRegular, &blob, false, true, true},
		{model.SetExecutable, &blob, true, true, true},
		{model.SetExecutable, &otherBlob, true, true, true},
		{model.Delete, nil, true, true, false},
		{model.SetSymlink, &blob, true, false, true},
	} {
		op, err := model.NewOperation(path, tc.tag, tc.target); if err != nil { t.Fatal(err) }
		input := model.ChangesetInput{RepoID: [16]byte{1}, Operations: []model.Operation{op}, Message: []byte{byte(i)}}
		if parent != nil {
			// A second parent is hashed ancestry, never a history/tree union.
			other, _ := model.NewTypedID(model.ChangesetKind, [32]byte{99}); second, _ := model.NewChangesetID(other)
			input.Parents = []model.ChangesetID{parent.Identity.Changeset, second}
		}
		source, err := model.NewChangeset(input); if err != nil { t.Fatal(err) }
		id, err := model.HashChangeset(context.Background(), source); if err != nil { t.Fatal(err) }
		identity := metadata.DerivedIdentity{Repository: input.RepoID, Changeset: id, Kind: "TREE", Version: 1}
		write, added, err := PrepareTreeWrite(context.Background(), identity, input, parent, frames, rewrite)
		if err != nil { t.Fatal(err) }
		for id, frame := range added { frames[id] = frame }
		step, used, err := DerivePathHistoryStep(context.Background(), source, write.Result, parent, frames, frames, path, budget)
		if err != nil || (step != nil) != tc.changed { t.Fatalf("transition %d: %v", i, err) }
		if step != nil {
			if step.Changeset != id || step.Repository != input.RepoID || step.Path != path || step.BeforePresent != tc.before || step.AfterPresent != tc.after { t.Fatal("wrong history identity or presence") }
			if parent != nil && step.FirstParent != parent.Identity.Changeset { t.Fatal("wrong first-parent history") }
			if step.Before != expectedBefore { t.Fatal("prior mode/blob or absent state lost") }
			if tc.after && step.After != op { t.Fatal("mode/blob transition lost") }
			if !tc.after && step.After != (model.Operation{}) { t.Fatal("absent after-state carried a row") }
		}
		exact := budget; exact.InputBytes = source.PayloadSize(); exact.Lookup = TreeLookupBudget{used.Pages, used.ReadBytes}
		if _, again, err := DerivePathHistoryStep(context.Background(), source, write.Result, parent, frames, frames, path, exact); err != nil || again != used { t.Fatal("exact combined lookup budget rejected") }
		exact.Lookup.ReadBytes--
		if got, _, err := DerivePathHistoryStep(context.Background(), source, write.Result, parent, frames, frames, path, exact); err != metadata.ErrResourceExhausted || got != nil { t.Fatal("history byte budget reset") }
		if got, _, err := DerivePathHistoryStep(context.Background(), source, write.Result, parent, frames, frames, missing, budget); err != nil || got != nil { t.Fatal("absent path fabricated history") }
		if parent != nil { lastParent = *parent }
		lastSource, lastCurrent = source, write.Result
		next := write.Result; parent = &next
		expectedBefore = model.Operation{}
		if tc.after { expectedBefore = op }
	}
	check := func(current metadata.DerivedResult, prior *metadata.DerivedResult, currentFrames, priorFrames map[TreePageID][]byte, limits PathHistoryBudget, want error) {
		t.Helper()
		if step, _, err := DerivePathHistoryStep(context.Background(), lastSource, current, prior, currentFrames, priorFrames, path, limits); err != want || step != nil { t.Fatalf("invalid history admitted: %v, want %v", err, want) }
	}
	check(lastCurrent, nil, frames, frames, budget, metadata.ErrFailedPrecondition)
	check(lastCurrent, &lastParent, nil, frames, budget, ErrTreePageMissing)
	check(lastCurrent, &lastParent, frames, nil, budget, ErrTreePageMissing)
	wrong := lastParent; wrong.Identity.Repository[0]++
	check(lastCurrent, &wrong, frames, frames, budget, metadata.ErrInvalidArgument)
	wrong = lastParent; wrong.Identity.Changeset = lastCurrent.Identity.Changeset
	check(lastCurrent, &wrong, frames, frames, budget, metadata.ErrInvalidArgument)
	wrong = lastCurrent; wrong.Identity.Kind = "other"
	check(wrong, &lastParent, frames, frames, budget, metadata.ErrInvalidArgument)
	wrong = lastCurrent; wrong.Identity.Changeset = lastParent.Identity.Changeset
	check(wrong, &lastParent, frames, frames, budget, metadata.ErrCorruptData)
	short := budget; short.InputBytes = lastSource.PayloadSize()-1
	check(lastCurrent, &lastParent, frames, frames, short, metadata.ErrResourceExhausted)
	short = budget; short.Lookup.Pages = 1
	check(lastCurrent, &lastParent, frames, frames, short, metadata.ErrResourceExhausted)
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if step, _, err := DerivePathHistoryStep(ctx, lastSource, lastCurrent, &lastParent, frames, frames, path, budget); err != context.Canceled || step != nil { t.Fatal("history cancellation lost") }
}
