// Package changesets validates internal requests before publication. Scope and
// object identities grant no authority; trusted composition must supply ports,
// finite budgets, and commit-time policy/expectation/retention checks.
package changesets

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

type BaseMode uint8

const (
	BaseRoot BaseMode = iota + 1
	BaseDetached
	BaseAliasAbsent
	BaseAliasPresent
)

type BaseExpectation struct {
	Mode               BaseMode
	Alias              string
	ExpectedTarget     model.ChangesetID
	ExpectedGeneration *uint64
}

const (
	AliasAbsentState uint8 = iota + 1
	AliasPresentState
)

type ParentLookup interface {
	GetPublication(context.Context, metadata.Scope, model.ChangesetID) (metadata.Publication, error)
}

// AliasLookup is a new consumer-owned contract, not an adapter for GetRef.
// Nil error asserts an authorized, complete authoritative snapshot: absent has
// an all-zero value; present has a valid target. Hidden ErrNotFound is failure.
type AliasLookup interface {
	LookupAlias(context.Context, metadata.Scope, string) (value metadata.RefValue, state uint8, err error)
}

type TreeBudget struct {
	MaxPages, MaxEntries, MaxReadBytes uint64
	MaxMemoryBytes, MaxSteps, MaxQueue uint64
}

type TreeInput struct {
	Root        bool
	FirstParent model.ChangesetID
	Changeset   model.Changeset
}

// TreeValidator is a new read-only contract. Nil means complete structural
// success for the entire simultaneous delta against the authorized, retained,
// complete exact first-parent tree, or the explicitly empty root base. Missing,
// partial or uncertain trees are errors. Providers must meter all work before
// admission against every budget, including cache hits and expanded contexts;
// they must use incremental paths/validated subtrees, never flatten a repository.
// Success proves neither durable blobs/pages nor publication or retention at a
// later commit point. No real provider is implemented by this package.
type TreeValidator interface {
	ValidateFinalTree(context.Context, metadata.Scope, TreeInput, TreeBudget) error
}

type Ports struct {
	Parents ParentLookup
	Aliases AliasLookup
	Trees   TreeValidator
}

type Budget struct {
	MaxPayloadBytes, MaxParents, MaxOperations, MaxAliasBytes uint64
	MaxDuration                                               time.Duration
	Tree                                                      TreeBudget
}

// validationError never renders its causes, which may contain protected data.
// Cause traversal remains available internally through errors.Is.
type validationError struct{ causes []error }

func (*validationError) Error() string     { return "changeset validation failed" }
func (e *validationError) Unwrap() []error { return append([]error(nil), e.causes...) }
func failure(causes ...error) error        { return &validationError{causes: causes} }

func dependencyFailure(err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, metadata.ErrDeadlineExceeded) {
		return failure(context.DeadlineExceeded, metadata.ErrDeadlineExceeded, err)
	}
	for _, known := range []error{
		context.Canceled, metadata.ErrInvalidArgument, metadata.ErrUnauthenticated,
		metadata.ErrPermissionDenied, metadata.ErrNotFound, metadata.ErrConflict,
		metadata.ErrFailedPrecondition, metadata.ErrResourceExhausted,
		metadata.ErrUnavailable, metadata.ErrCorruptData, metadata.ErrOutcomeUnknown,
	} {
		if errors.Is(err, known) {
			return failure(err)
		}
	}
	return failure(metadata.ErrUnavailable, err)
}

func contextFailure(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return dependencyFailure(err)
	}
	return nil
}

func portFailure(ctx context.Context, err error) error {
	if ctxErr := contextFailure(ctx); ctxErr != nil {
		if err != nil {
			return failure(ctxErr, dependencyFailure(err))
		}
		return ctxErr
	}
	if err != nil {
		return dependencyFailure(err)
	}
	return nil
}

func nilPort(port any) bool {
	if port == nil {
		return true
	}
	v := reflect.ValueOf(port)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func validBudget(b Budget) bool {
	t := b.Tree
	return b.MaxDuration > 0 && b.MaxPayloadBytes > 0 && b.MaxPayloadBytes <= model.MaxChangesetPayload &&
		b.MaxParents > 0 && b.MaxParents <= model.MaxParents &&
		b.MaxOperations > 0 && b.MaxOperations <= model.MaxOperations && b.MaxAliasBytes > 0 &&
		t.MaxPages > 0 && t.MaxEntries > 0 && t.MaxReadBytes > 0 &&
		t.MaxMemoryBytes > 0 && t.MaxSteps > 0 && t.MaxQueue > 0
}

func validBase(b BaseExpectation, parents []model.ChangesetID) bool {
	zeroTarget := b.ExpectedTarget == (model.ChangesetID{})
	switch b.Mode {
	case BaseRoot, BaseDetached:
		return b.Alias == "" && zeroTarget && b.ExpectedGeneration == nil &&
			((b.Mode == BaseRoot && len(parents) == 0) || (b.Mode == BaseDetached && len(parents) > 0))
	case BaseAliasAbsent:
		return b.Alias != "" && zeroTarget && b.ExpectedGeneration == nil
	case BaseAliasPresent:
		return b.Alias != "" && b.ExpectedTarget.Validate() == nil && b.ExpectedGeneration != nil &&
			len(parents) > 0 && b.ExpectedTarget == parents[0]
	}
	return false
}

// checkSets closes the constructor/decoder gap without interpreting a base
// tree. Only simultaneous SET ancestors are intrinsically impossible. DELETEs
// may enable valid file/directory replacements and must reach the tree port.
func checkSets(ctx context.Context, operations []model.Operation) error {
	sets := make([]string, 0, len(operations))
	for _, op := range operations {
		if err := contextFailure(ctx); err != nil {
			return err
		}
		if op.Tag() != model.Delete {
			sets = append(sets, string(op.Path().Bytes()))
		}
	}
	for _, path := range sets {
		if err := contextFailure(ctx); err != nil {
			return err
		}
		prefix := path + "/"
		i := sort.SearchStrings(sets, prefix)
		if i < len(sets) && strings.HasPrefix(sets[i], prefix) {
			return failure(metadata.ErrInvalidArgument)
		}
	}
	return contextFailure(ctx)
}

// Validate returns an owned changeset only after every required check succeeds.
// Callers must not mutate input during validation/copy. Dependencies are caller
// owned: no Close, retry, state retention, background work or ref mutation occurs.
// All calls share one deadline; noncooperative providers cannot be interrupted.
func Validate(ctx context.Context, scope metadata.Scope, input model.ChangesetInput,
	base BaseExpectation, budget Budget, ports Ports) (model.Changeset, error) {
	var zero model.Changeset
	if ctx == nil {
		return zero, failure(metadata.ErrInvalidArgument)
	}
	if err := contextFailure(ctx); err != nil {
		return zero, err
	}
	if !validBudget(budget) {
		return zero, failure(metadata.ErrInvalidArgument)
	}
	ctx, cancel := context.WithTimeout(ctx, budget.MaxDuration)
	defer cancel()
	if !validBase(base, input.Parents) {
		return zero, failure(metadata.ErrInvalidArgument)
	}
	var generation uint64
	if base.ExpectedGeneration != nil {
		generation = *base.ExpectedGeneration
	}
	if err := contextFailure(ctx); err != nil {
		return zero, err
	}
	size, err := model.ValidateChangeset(input)
	if ctxErr := contextFailure(ctx); ctxErr != nil {
		return zero, ctxErr
	}
	if err != nil {
		return zero, failure(metadata.ErrInvalidArgument, err)
	}
	if input.RepoID != scope.Repository {
		return zero, failure(metadata.ErrInvalidArgument)
	}
	if size > budget.MaxPayloadBytes || uint64(len(input.Parents)) > budget.MaxParents ||
		uint64(len(input.Operations)) > budget.MaxOperations || uint64(len(base.Alias)) > budget.MaxAliasBytes {
		return zero, failure(metadata.ErrResourceExhausted)
	}
	if err := checkSets(ctx, input.Operations); err != nil {
		return zero, err
	}
	aliasMode := base.Mode == BaseAliasAbsent || base.Mode == BaseAliasPresent
	if nilPort(ports.Trees) || (len(input.Parents) > 0 && nilPort(ports.Parents)) ||
		(aliasMode && nilPort(ports.Aliases)) {
		return zero, failure(metadata.ErrInvalidArgument)
	}
	owned, err := model.NewChangeset(input)
	if ctxErr := contextFailure(ctx); ctxErr != nil {
		return zero, ctxErr
	}
	if err != nil {
		return zero, failure(metadata.ErrInvalidArgument, err)
	}
	// Snapshot is independently owned; no dependency can redirect later lookups
	// by mutating the caller's original parents after admission.
	parents := owned.Snapshot().Parents
	for _, parent := range parents {
		if err := contextFailure(ctx); err != nil {
			return zero, err
		}
		publication, err := ports.Parents.GetPublication(ctx, scope, parent)
		if err := portFailure(ctx, err); err != nil {
			return zero, err
		}
		if publication.Repository != scope.Repository || publication.Changeset != parent ||
			publication.ID == "" || publication.Event == "" {
			return zero, failure(metadata.ErrCorruptData)
		}
	}
	if aliasMode {
		if err := contextFailure(ctx); err != nil {
			return zero, err
		}
		value, state, err := ports.Aliases.LookupAlias(ctx, scope, base.Alias)
		if err := portFailure(ctx, err); err != nil {
			return zero, err
		}
		if (state != AliasAbsentState && state != AliasPresentState) ||
			(state == AliasAbsentState && value != (metadata.RefValue{})) ||
			(state == AliasPresentState && value.Target.Validate() != nil) {
			return zero, failure(metadata.ErrCorruptData)
		}
		if (base.Mode == BaseAliasAbsent && state != AliasAbsentState) ||
			(base.Mode == BaseAliasPresent && (state != AliasPresentState ||
				value.Target != base.ExpectedTarget || value.Generation != generation)) {
			return zero, failure(metadata.ErrConflict)
		}
	}
	tree := TreeInput{Root: len(parents) == 0, Changeset: owned}
	if !tree.Root {
		tree.FirstParent = parents[0]
	}
	if err := contextFailure(ctx); err != nil {
		return zero, err
	}
	err = ports.Trees.ValidateFinalTree(ctx, scope, tree, budget.Tree)
	if err := portFailure(ctx, err); err != nil {
		return zero, err
	}
	return owned, nil
}
