package ci

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"testing"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/query"
)

func bisectFixture(t *testing.T, count int) (*query.CanonicalGraph, []model.ChangesetID) {
	t.Helper(); ctx := context.Background(); repo := [16]byte{9}
	graph, err := query.NewCanonicalGraph(repo,query.GraphBudget{Nodes:100,References:1000},4096); if err != nil { t.Fatal(err) }
	var ids []model.ChangesetID
	for i := 0; i < count; i++ {
		input := model.ChangesetInput{RepoID:repo,Message:[]byte(fmt.Sprintf("revision %d",i))}
		if i != 0 { input.Parents = []model.ChangesetID{ids[i-1]} }
		value, err := model.NewChangeset(input); if err != nil { t.Fatal(err) }
		id, err := model.HashChangeset(ctx,value); if err != nil { t.Fatal(err) }
		var frame bytes.Buffer; if err := model.EncodeChangeset(ctx,&frame,value); err != nil { t.Fatal(err) }
		if _, err := graph.AddFrame(ctx,id,frame.Bytes()); err != nil { t.Fatal(err) }
		ids = append(ids,id)
	}
	return graph,ids
}

func TestFirstParentBisectUnknownSkippedAndBoundary(t *testing.T) {
	graph, ids := bisectFixture(t,7); ctx := context.Background()
	budget := BisectBudget{7,6,20,6}
	observations := []RevisionObservation{{ids[0],OutcomePass},{ids[6],OutcomeFail}}
	got, used, err := AnalyzeFirstParentBisect(ctx,graph,ids[0],ids[6],observations,budget)
	if err != nil || got.State != BisectUncertain || !reflect.DeepEqual(got.Candidates,ids[1:]) || !got.HasNext || got.Next != ids[3] || used != (BisectUsage{7,6,2}) { t.Fatal(got,used,err) }
	observations = append(observations,RevisionObservation{ids[3],OutcomePass},RevisionObservation{ids[4],OutcomeSkipped})
	got, _, err = AnalyzeFirstParentBisect(ctx,graph,ids[0],ids[6],observations,budget)
	if err != nil || !reflect.DeepEqual(got.Candidates,ids[4:]) || got.Next != ids[5] || !got.HasNext || got.State != BisectUncertain { t.Fatal(got,err) }
	// A skipped possible boundary cannot be treated as a pass or culprit.
	observations = append(observations,RevisionObservation{ids[5],OutcomeFail},RevisionObservation{ids[1],OutcomePass},RevisionObservation{ids[2],OutcomePass})
	got, _, err = AnalyzeFirstParentBisect(ctx,graph,ids[0],ids[6],observations,budget)
	if err != nil || !reflect.DeepEqual(got.Candidates,ids[4:6]) || got.HasNext || got.State != BisectUncertain { t.Fatal(got,err) }
	observations = append(observations,RevisionObservation{ids[4],OutcomeFail})
	got, _, err = AnalyzeFirstParentBisect(ctx,graph,ids[0],ids[6],observations,budget)
	if err != nil || got.State != BisectObservedBoundary || !reflect.DeepEqual(got.Candidates,ids[4:5]) || got.HasNext { t.Fatal(got,err) }
	got.Candidates[0] = ids[0]
	again, _, err := AnalyzeFirstParentBisect(ctx,graph,ids[0],ids[6],observations,budget)
	if err != nil || again.Candidates[0] != ids[4] { t.Fatal("output aliases retained state",again,err) }
}

func TestFirstParentBisectExplicitUncertaintyAndLimits(t *testing.T) {
	graph, ids := bisectFixture(t,5); ctx := context.Background(); budget := BisectBudget{5,4,10,4}
	base := []RevisionObservation{{ids[0],OutcomePass},{ids[4],OutcomeFail}}
	for _, tc := range []struct{ extra []RevisionObservation; state BisectState }{
		{[]RevisionObservation{{ids[1],OutcomeFail},{ids[3],OutcomePass}},BisectNonMonotonic},
		{[]RevisionObservation{{ids[2],OutcomeFail},{ids[2],OutcomePass}},BisectFlaky},
	} {
		got, _, err := AnalyzeFirstParentBisect(ctx,graph,ids[0],ids[4],append(append([]RevisionObservation(nil),base...),tc.extra...),budget)
		if err != nil || got.State != tc.state || got.Candidates != nil || got.HasNext { t.Fatal(got,err) }
	}
	got, _, err := AnalyzeFirstParentBisect(ctx,graph,ids[0],ids[4],nil,budget)
	if err != nil || got.State != BisectUncertain || got.Candidates != nil || !got.HasNext || got.Next != ids[0] { t.Fatal(got,err) }
	for _, short := range []BisectBudget{{4,4,10,4},{5,3,10,4},{5,4,1,4},{5,4,10,3},{}} {
		got, _, err := AnalyzeFirstParentBisect(ctx,graph,ids[0],ids[4],base,short)
		if err != ErrBisectBudget || !reflect.DeepEqual(got,BisectAnalysis{}) { t.Fatal(got,err) }
	}
	for _, observations := range [][]RevisionObservation{{{ids[0],TestOutcome(99)}},{{model.ChangesetID{},OutcomePass}}} {
		got, _, err := AnalyzeFirstParentBisect(ctx,graph,ids[0],ids[4],observations,budget)
		if err != ErrBisectInput || !reflect.DeepEqual(got,BisectAnalysis{}) { t.Fatal(got,err) }
	}
	if got, _, err := AnalyzeFirstParentBisect(ctx,graph,ids[4],ids[0],base,budget); err != ErrBisectLineage || !reflect.DeepEqual(got,BisectAnalysis{}) { t.Fatal(got,err) }
	cancelled,cancel := context.WithCancel(ctx); cancel()
	if got, _, err := AnalyzeFirstParentBisect(cancelled,graph,ids[0],ids[4],base,budget); err != context.Canceled || !reflect.DeepEqual(got,BisectAnalysis{}) { t.Fatal(got,err) }
}

func TestFirstParentBisectMergeAndCancellation(t *testing.T) {
	graph, ids := bisectFixture(t,4); ctx := context.Background(); repo := [16]byte{9}
	makeSource := func(parents []model.ChangesetID, message string) model.ChangesetID {
		value, err := model.NewChangeset(model.ChangesetInput{RepoID:repo,Parents:parents,Message:[]byte(message)}); if err != nil { t.Fatal(err) }
		id, err := model.HashChangeset(ctx,value); if err != nil { t.Fatal(err) }
		var frame bytes.Buffer; if err := model.EncodeChangeset(ctx,&frame,value); err != nil { t.Fatal(err) }
		if _, err := graph.AddFrame(ctx,id,frame.Bytes()); err != nil { t.Fatal(err) }; return id
	}
	other := makeSource(nil,"independent root")
	merge := makeSource([]model.ChangesetID{ids[3],other},"merge")
	budget := BisectBudget{5,5,10,4}
	observations := []RevisionObservation{{ids[0],OutcomePass},{merge,OutcomeFail}}
	got, usage, err := AnalyzeFirstParentBisect(ctx,graph,ids[0],merge,observations,budget)
	if err != nil || usage.ParentReferences != 5 || len(got.Candidates) != 4 { t.Fatal(got,usage,err) }
	if got, _, err := AnalyzeFirstParentBisect(ctx,graph,other,merge,nil,budget); err != ErrBisectLineage || !reflect.DeepEqual(got,BisectAnalysis{}) { t.Fatal(got,err) }
	outside := append(append([]RevisionObservation(nil),observations...),RevisionObservation{other,OutcomePass})
	if got, _, err := AnalyzeFirstParentBisect(ctx,graph,ids[0],merge,outside,budget); err != ErrBisectInput || !reflect.DeepEqual(got,BisectAnalysis{}) { t.Fatal(got,err) }
	counter := &bisectCancelContext{Context:ctx}
	if _, _, err := AnalyzeFirstParentBisect(counter,graph,ids[0],merge,observations,budget); err != nil { t.Fatal(err) }
	// Exercise every cancellation checkpoint, including after candidate staging.
	for stop := 1; stop <= counter.calls; stop++ {
		cancel := &bisectCancelContext{Context:ctx,stop:stop}
		got, _, err := AnalyzeFirstParentBisect(cancel,graph,ids[0],merge,observations,budget)
		if err != context.Canceled || !reflect.DeepEqual(got,BisectAnalysis{}) { t.Fatal(stop,got,err) }
	}
}

type bisectCancelContext struct { context.Context; calls, stop int }
func (c *bisectCancelContext) Err() error { c.calls++; if c.stop != 0 && c.calls >= c.stop { return context.Canceled }; return nil }

func TestFirstParentBisectUnknownOutsideAdjacentBoundary(t *testing.T) {
	graph, ids := bisectFixture(t,5); ctx := context.Background(); budget := BisectBudget{5,4,10,4}
	observations := []RevisionObservation{{ids[0],OutcomePass},{ids[0],OutcomePass},{ids[1],OutcomeUnknown},{ids[2],OutcomePass},{ids[3],OutcomeFail},{ids[4],OutcomeFail}}
	got, used, err := AnalyzeFirstParentBisect(ctx,graph,ids[0],ids[4],observations,budget)
	if err != nil || used.Observations != 6 || got.State != BisectUncertain || !reflect.DeepEqual(got.Candidates,ids[3:4]) || !got.HasNext || got.Next != ids[1] { t.Fatal(got,used,err) }
	// A later failure at this unknown exposes a regression/recovery; do not
	// report the adjacent boundary as a fabricated unique culprit beforehand.
	observations = append(observations,RevisionObservation{ids[1],OutcomeFail})
	got, _, err = AnalyzeFirstParentBisect(ctx,graph,ids[0],ids[4],observations,budget)
	if err != nil || got.State != BisectNonMonotonic || got.Candidates != nil || got.HasNext { t.Fatal(got,err) }
	for _, g := range []*query.CanonicalGraph{nil,&query.CanonicalGraph{}} {
		if got, _, err := AnalyzeFirstParentBisect(ctx,g,ids[0],ids[4],nil,budget); err == nil || !reflect.DeepEqual(got,BisectAnalysis{}) { t.Fatal(got,err) }
	}
	if got, _, err := AnalyzeFirstParentBisect(nil,graph,ids[0],ids[4],nil,budget); err != ErrBisectInput || !reflect.DeepEqual(got,BisectAnalysis{}) { t.Fatal(got,err) }
	if got, _, err := AnalyzeFirstParentBisect(ctx,graph,ids[0],ids[0],nil,budget); err != ErrBisectInput || !reflect.DeepEqual(got,BisectAnalysis{}) { t.Fatal(got,err) }
}
