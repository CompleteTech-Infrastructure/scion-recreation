package ci

import (
	"context"
	"errors"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/query"
)

var (
	ErrBisectInput = errors.New("invalid private bisect input")
	ErrBisectBudget = errors.New("private bisect budget exceeded")
	ErrBisectLineage = errors.New("bisect endpoints are not on supplied first-parent lineage")
)

// TestOutcome is a private observation, not an attestation or scheduler state.
// Unknown and skipped are never interpreted as passes. Conflicting pass/fail
// observations of one exact ID mark the entire analysis flaky.
type TestOutcome uint8
const (
	OutcomeUnknown TestOutcome = iota
	OutcomePass
	OutcomeFail
	OutcomeSkipped
)
type RevisionObservation struct { Revision model.ChangesetID; Outcome TestOutcome }
type BisectBudget struct { Revisions, ParentReferences, Observations, Candidates uint64 }
type BisectUsage struct { Revisions, ParentReferences, Observations uint64 }
type BisectState uint8
const (
	BisectUncertain BisectState = iota
	BisectFlaky
	BisectNonMonotonic
	BisectObservedBoundary
)

// Candidates is an oldest-first possible transition interval under the explicit
// monotonic hypothesis, NOT a claim that any revision caused a failure. Even
// ObservedBoundary only describes all supplied stable observations on this
// first-parent interval; it cannot prove absence of future flakes or causality.
// Next is a suggested unknown revision, never an instruction to execute tests.
// Skipped-only uncertainty may have no next revision. Outputs are caller-owned.
type BisectAnalysis struct {
	State BisectState
	Candidates []model.ChangesetID
	Next model.ChangesetID
	HasNext bool
}

// AnalyzeFirstParentBisect walks from bad to good inclusively through canonical
// parent-zero metadata. Other parents are not unioned into this linear search.
// IDs must differ and good must be on that chain. All observation IDs must be
// inside this exact interval; repeated observations are admitted and aggregated.
// Stable pass at good and fail at bad are required before narrowing candidates.
// Any observed failure followed by a pass is explicit non-monotonic uncertainty.
// Any pass/fail disagreement for one ID is explicit flaky uncertainty instead.
// Neither condition returns candidates. Missing/skipped interior observations
// keep State uncertain, even if observed boundaries happen to be adjacent.
//
// PRIVATE, deterministic, in-process analysis only. The caller must bind all
// observations to the same exact test/suite/environment/policy and establish
// publication and permission independently. These claims are not authenticated
// here. Graph and observations must remain stable. No commands, fetches, test
// runs, authorization, persistence, remediation or public workflow are provided.
// Limits bound retained IDs, admitted parent references, and observation scans.
// The graph API returns an owned parent list before admission: one additional
// copy of at most model.MaxParents (1,024) references may occur on rejection.
// Limits do not measure RSS. Failure/cancellation returns zero analysis with usage.
func AnalyzeFirstParentBisect(ctx context.Context, graph *query.CanonicalGraph, good, bad model.ChangesetID, observations []RevisionObservation, budget BisectBudget) (BisectAnalysis, BisectUsage, error) {
	var zero BisectAnalysis
	var usage BisectUsage
	if ctx == nil || graph == nil || good.Validate() != nil || bad.Validate() != nil || good == bad { return zero, usage, ErrBisectInput }
	if err := ctx.Err(); err != nil { return zero, usage, err }
	if budget.Revisions == 0 || budget.Revisions > 100000 || budget.ParentReferences == 0 || budget.ParentReferences > 1000000 || budget.Observations == 0 || budget.Observations > 1000000 || budget.Candidates == 0 || budget.Candidates > 100000 { return zero, usage, ErrBisectBudget }
	if uint64(len(observations)) > budget.Observations { return zero, usage, ErrBisectBudget }
	var lineage []model.ChangesetID
	for id := bad; ; {
		if err := ctx.Err(); err != nil { return zero, usage, err }
		if usage.Revisions == budget.Revisions { return zero, usage, ErrBisectBudget }
		node, ok := graph.Lookup(id); if !ok { return zero, usage, ErrBisectLineage }
		usage.Revisions++
		lineage = append(lineage,id)
		if id == good { break }
		// Parents returns a bounded owned copy (at most model.MaxParents).
		parents := node.Parents()
		if uint64(len(parents)) > budget.ParentReferences-usage.ParentReferences { return zero, usage, ErrBisectBudget }
		usage.ParentReferences += uint64(len(parents))
		if len(parents) == 0 { return zero, usage, ErrBisectLineage }
		id = parents[0]
	}
	for i,j := 0,len(lineage)-1; i < j; i,j = i+1,j-1 { lineage[i],lineage[j] = lineage[j],lineage[i] }
	positions := make(map[model.ChangesetID]int,len(lineage))
	for i,id := range lineage { if err := ctx.Err(); err != nil { return zero, usage, err }; positions[id] = i }
	states := make([]uint8,len(lineage))
	for _, observation := range observations {
		if err := ctx.Err(); err != nil { return zero, usage, err }
		usage.Observations++
		index, ok := positions[observation.Revision]
		if !ok || observation.Outcome > OutcomeSkipped { return zero, usage, ErrBisectInput }
		switch observation.Outcome {
		case OutcomePass: states[index] |= 1
		case OutcomeFail: states[index] |= 2
		case OutcomeSkipped: states[index] |= 4
		}
	}
	result := BisectAnalysis{State:BisectUncertain}
	flaky, nonmonotonic, sawFail, incomplete := false,false,false,false
	lastPass, firstFail := -1,len(lineage)
	for i,state := range states {
		if err := ctx.Err(); err != nil { return zero, usage, err }
		switch state & 3 {
		case 0: incomplete = true
		case 1: lastPass = i; if sawFail { nonmonotonic = true }
		case 2: sawFail = true; if firstFail == len(lineage) { firstFail = i }
		case 3: flaky = true
		}
	}
	if flaky { result.State = BisectFlaky } else if nonmonotonic { result.State = BisectNonMonotonic } else if states[0]&3 == 1 && states[len(states)-1]&3 == 2 {
		count := firstFail-lastPass
		if uint64(count) > budget.Candidates { return zero, usage, ErrBisectBudget }
		result.Candidates = append([]model.ChangesetID(nil),lineage[lastPass+1:firstFail+1]...)
		if !incomplete { result.State = BisectObservedBoundary }
		// Choose the unknown nearest the midpoint of the bounded interval;
		// ties favor the older revision. Skipped observations are not retried.
		mid, distance := (lastPass+1+firstFail)/2,len(lineage)+1
		for i := lastPass+1; i < firstFail; i++ {
			if err := ctx.Err(); err != nil { return zero, usage, err }
			if states[i] != 0 { continue }
			d := i-mid; if d < 0 { d = -d }
			if d < distance { result.Next,result.HasNext,distance = lineage[i],true,d }
		}
	}
	// Unknowns outside a narrowed interval also prevent observed monotonicity.
	// Endpoint evidence is needed before a candidate interval can be returned.
	if result.State == BisectUncertain && !result.HasNext {
		for i,state := range states {
			if err := ctx.Err(); err != nil { return zero, usage, err }
			if state == 0 { result.Next,result.HasNext = lineage[i],true; break }
		}
	}
	if err := ctx.Err(); err != nil { return zero, usage, err }
	return result,usage,nil
}
