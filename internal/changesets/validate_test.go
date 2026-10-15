package changesets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

// These fakes prove ordered calls, alias comparison and complete-tree contract
// plumbing only. Scripted tree replies do not evaluate trees or prove authority,
// completeness, durability, retention, publication, wire mapping or real storage.
type parentFake func(context.Context, metadata.Scope, model.ChangesetID) (metadata.Publication, error)
type aliasFake func(context.Context, metadata.Scope, string) (metadata.RefValue, uint8, error)
type treeFake func(context.Context, metadata.Scope, TreeInput, TreeBudget) error

func (f parentFake) GetPublication(c context.Context, s metadata.Scope, id model.ChangesetID) (metadata.Publication, error) {
	return f(c, s, id)
}
func (f aliasFake) LookupAlias(c context.Context, s metadata.Scope, name string) (metadata.RefValue, uint8, error) {
	return f(c, s, name)
}
func (f treeFake) ValidateFinalTree(c context.Context, s metadata.Scope, in TreeInput, b TreeBudget) error {
	return f(c, s, in, b)
}

func parentID(n byte) model.ChangesetID {
	id, _ := model.NewTypedID(model.ChangesetKind, [32]byte{n})
	p, _ := model.NewChangesetID(id)
	return p
}
func edit(t *testing.T, path string, tag model.OperationTag) model.Operation {
	t.Helper()
	p, err := model.NewPath([]byte(path))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := model.NewTypedID(model.BlobKind, [32]byte{9})
	b, _ := model.NewBlobID(id)
	var target *model.BlobID
	if tag != model.Delete {
		target = &b
	}
	op, err := model.NewOperation(p, tag, target)
	if err != nil {
		t.Fatal(err)
	}
	return op
}
func fixture() (metadata.Scope, model.ChangesetInput, Budget) {
	s := metadata.Scope{Repository: [16]byte{7}, Principal: "requested-principal", Session: "requested-session", PolicyVersion: 0}
	b := Budget{MaxPayloadBytes: 4096, MaxParents: 8, MaxOperations: 16, MaxAliasBytes: 64,
		MaxDuration: time.Second, Tree: TreeBudget{11, 12, 13, 14, 15, 16}}
	return s, model.ChangesetInput{RepoID: s.Repository}, b
}
func publication(s metadata.Scope, id model.ChangesetID) metadata.Publication {
	return metadata.Publication{Repository: s.Repository, Changeset: id, ID: "publication", Event: "event"}
}
func assertFailure(t *testing.T, value model.Changeset, err, want error) {
	t.Helper()
	if err == nil || !errors.Is(err, want) || !reflect.DeepEqual(value, model.Changeset{}) {
		t.Fatalf("expected zero changeset and %v; got zero=%v, error=%v", want, reflect.DeepEqual(value, model.Changeset{}), err)
	}
	if err.Error() != "changeset validation failed" {
		t.Fatalf("unsafe error text: %q", err.Error())
	}
}
func noCalls(t *testing.T) Ports {
	t.Helper()
	return Ports{
		Parents: parentFake(func(context.Context, metadata.Scope, model.ChangesetID) (metadata.Publication, error) {
			t.Fatal("unexpected parent lookup")
			return metadata.Publication{}, nil
		}),
		Aliases: aliasFake(func(context.Context, metadata.Scope, string) (metadata.RefValue, uint8, error) {
			t.Fatal("unexpected alias lookup")
			return metadata.RefValue{}, 0, nil
		}),
		Trees: treeFake(func(context.Context, metadata.Scope, TreeInput, TreeBudget) error {
			t.Fatal("unexpected tree lookup")
			return nil
		}),
	}
}
func encoded(t *testing.T, v model.Changeset) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := model.EncodeChangeset(context.Background(), &b, v); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// V01-V05,V14: all successful modes require exactly one scripted tree success.
func TestValidateModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode BaseMode
		n    int
		gen  uint64
	}{{"root", BaseRoot, 0, 0}, {"detached_repeated", BaseDetached, 3, 0},
		{"absent_root", BaseAliasAbsent, 0, 0}, {"absent_parents", BaseAliasAbsent, 3, 0},
		{"present_zero", BaseAliasPresent, 3, 0}, {"present_max", BaseAliasPresent, 3, math.MaxUint64}} {
		t.Run(tc.name, func(t *testing.T) {
			s, in, b := fixture()
			in.Encoding = []byte{}
			in.Parents = []model.ChangesetID{parentID(1), parentID(1), parentID(2)}[:tc.n]
			base := BaseExpectation{Mode: tc.mode}
			aliasMode := tc.mode == BaseAliasAbsent || tc.mode == BaseAliasPresent
			if aliasMode {
				base.Alias = "\xff/opaque\x00alias"
			}
			if tc.mode == BaseAliasPresent {
				base.ExpectedTarget, base.ExpectedGeneration = in.Parents[0], &tc.gen
			}
			want, _ := model.NewChangeset(in)
			var calls []string
			p := noCalls(t)
			p.Parents = parentFake(func(c context.Context, got metadata.Scope, id model.ChangesetID) (metadata.Publication, error) {
				if got != s || id != in.Parents[len(calls)] {
					t.Fatal("parent scope/order changed")
				}
				calls = append(calls, "parent")
				return publication(s, id), nil
			})
			if aliasMode {
				p.Aliases = aliasFake(func(c context.Context, got metadata.Scope, name string) (metadata.RefValue, uint8, error) {
					if got != s || name != base.Alias || len(calls) != tc.n {
						t.Fatal("alias scope/name/order changed")
					}
					calls = append(calls, "alias")
					if tc.mode == BaseAliasPresent {
						return metadata.RefValue{Target: parentID(1), Generation: tc.gen}, AliasPresentState, nil
					}
					return metadata.RefValue{}, AliasAbsentState, nil
				})
			}
			p.Trees = treeFake(func(c context.Context, got metadata.Scope, tree TreeInput, budget TreeBudget) error {
				first := model.ChangesetID{}
				if tc.n > 0 {
					first = in.Parents[0]
				}
				if got != s || tree.Root != (tc.n == 0) || tree.FirstParent != first || budget != b.Tree ||
					!bytes.Equal(encoded(t, tree.Changeset), encoded(t, want)) {
					t.Fatal("tree contract changed")
				}
				calls = append(calls, "tree")
				return nil
			})
			got, err := Validate(context.Background(), s, in, base, b, p)
			if err != nil || !bytes.Equal(encoded(t, got), encoded(t, want)) || got.Snapshot().Encoding == nil {
				t.Fatalf("mode failed: %v", err)
			}
			count := tc.n + 1
			if aliasMode {
				count++
			}
			if len(calls) != count || calls[count-1] != "tree" {
				t.Fatal("unexpected call count/order")
			}
		})
	}
}

// V03,V04: malformed unions fail before any dependency, including omitted gen.
func TestValidateExpectationUnion(t *testing.T) {
	g := uint64(0)
	for name, base := range map[string]BaseExpectation{
		"zero": {}, "unknown": {Mode: 255}, "root_parents": {Mode: BaseRoot},
		"detached_empty": {Mode: BaseDetached}, "root_alias": {Mode: BaseRoot, Alias: "a"},
		"detached_target": {Mode: BaseDetached, ExpectedTarget: parentID(1)},
		"root_generation": {Mode: BaseRoot, ExpectedGeneration: &g},
		"absent_name":     {Mode: BaseAliasAbsent}, "absent_target": {Mode: BaseAliasAbsent, Alias: "a", ExpectedTarget: parentID(1)},
		"absent_generation":   {Mode: BaseAliasAbsent, Alias: "a", ExpectedGeneration: &g},
		"present_empty":       {Mode: BaseAliasPresent, Alias: "a", ExpectedTarget: parentID(1), ExpectedGeneration: &g},
		"present_name":        {Mode: BaseAliasPresent, ExpectedTarget: parentID(1), ExpectedGeneration: &g},
		"present_target":      {Mode: BaseAliasPresent, Alias: "a", ExpectedGeneration: &g},
		"present_generation":  {Mode: BaseAliasPresent, Alias: "a", ExpectedTarget: parentID(1)},
		"present_wrong_first": {Mode: BaseAliasPresent, Alias: "a", ExpectedTarget: parentID(2), ExpectedGeneration: &g},
	} {
		t.Run(name, func(t *testing.T) {
			s, in, b := fixture()
			if name != "detached_empty" && name != "present_empty" && base.Mode != BaseRoot {
				in.Parents = []model.ChangesetID{parentID(1)}
			}
			if name == "root_parents" {
				in.Parents = []model.ChangesetID{parentID(1)}
			}
			v, err := Validate(context.Background(), s, in, base, b, noCalls(t))
			assertFailure(t, v, err, metadata.ErrInvalidArgument)
		})
	}
}

// V04,V05: errors are never authoritative absence; successful tuples are checked.
func TestValidateAliasTuples(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  BaseMode
		state uint8
		value metadata.RefValue
		want  error
	}{{"target", BaseAliasPresent, 2, metadata.RefValue{Target: parentID(2)}, metadata.ErrConflict},
		{"generation", BaseAliasPresent, 2, metadata.RefValue{Target: parentID(1), Generation: 1}, metadata.ErrConflict},
		{"present_for_absent", BaseAliasAbsent, 2, metadata.RefValue{Target: parentID(1)}, metadata.ErrConflict},
		{"absent_for_present", BaseAliasPresent, 1, metadata.RefValue{}, metadata.ErrConflict},
		{"zero_tag", BaseAliasAbsent, 0, metadata.RefValue{}, metadata.ErrCorruptData},
		{"unknown_tag", BaseAliasAbsent, 3, metadata.RefValue{}, metadata.ErrCorruptData},
		{"absent_value", BaseAliasAbsent, 1, metadata.RefValue{Generation: 1}, metadata.ErrCorruptData},
		{"invalid_present", BaseAliasAbsent, 2, metadata.RefValue{}, metadata.ErrCorruptData}} {
		t.Run(tc.name, func(t *testing.T) {
			s, in, b := fixture()
			in.Parents = []model.ChangesetID{parentID(1)}
			g := uint64(0)
			base := BaseExpectation{Mode: tc.mode, Alias: "a"}
			if tc.mode == BaseAliasPresent {
				base.ExpectedTarget, base.ExpectedGeneration = parentID(1), &g
			}
			p := noCalls(t)
			p.Parents = parentFake(func(c context.Context, s metadata.Scope, id model.ChangesetID) (metadata.Publication, error) {
				return publication(s, id), nil
			})
			calls := 0
			p.Aliases = aliasFake(func(context.Context, metadata.Scope, string) (metadata.RefValue, uint8, error) {
				calls++
				return tc.value, tc.state, nil
			})
			v, err := Validate(context.Background(), s, in, base, b, p)
			assertFailure(t, v, err, tc.want)
			if calls != 1 {
				t.Fatal("alias retried")
			}
		})
	}
}

// V06: only public constructors and valid/zero model values are used.
func TestValidateGrammar(t *testing.T) {
	for _, name := range []string{"zero_operation", "zero_parent", "unsorted", "duplicate", "repository"} {
		t.Run(name, func(t *testing.T) {
			s, in, b := fixture()
			base := BaseExpectation{Mode: BaseRoot}
			switch name {
			case "zero_operation":
				in.Operations = []model.Operation{{}}
			case "zero_parent":
				in.Parents, base.Mode = []model.ChangesetID{{}}, BaseDetached
			case "unsorted":
				in.Operations = []model.Operation{edit(t, "b", model.Delete), edit(t, "a", model.Delete)}
			case "duplicate":
				in.Operations = []model.Operation{edit(t, "a", model.SetRegular), edit(t, "a", model.Delete)}
			case "repository":
				in.RepoID[0]++
			}
			v, err := Validate(context.Background(), s, in, base, b, noCalls(t))
			assertFailure(t, v, err, metadata.ErrInvalidArgument)
		})
	}
}

func TestModelConstructorBoundary(t *testing.T) {
	p, _ := model.NewPath([]byte("a"))
	zero := model.BlobID{}
	id, _ := model.NewTypedID(model.BlobKind, [32]byte{1})
	b, _ := model.NewBlobID(id)
	for _, tc := range []struct {
		tag    model.OperationTag
		target *model.BlobID
	}{
		{model.Delete, &b}, {model.SetRegular, nil}, {model.SetExecutable, &zero}, {255, &b},
	} {
		if _, err := model.NewOperation(p, tc.tag, tc.target); err == nil {
			t.Fatal("invalid tag/target admitted by model")
		}
	}
	for _, raw := range []string{"", "/a", "a/../b", "a//b", "a\x00b"} {
		if _, err := model.NewPath([]byte(raw)); err == nil {
			t.Fatalf("invalid path %q admitted by model", raw)
		}
	}
	if _, err := model.NewMetadata(nil, 0, 1440); err == nil {
		t.Fatal("invalid offset admitted by model")
	}
	if _, err := model.NewChangesetID(id); err == nil {
		t.Fatal("blob used as changeset ID")
	}
}

// V07-V09: canonical simultaneous vectors assert forwarding and SCRIPTED replies.
// The base descriptions label fixtures; these fakes contain no tree algorithm.
func TestValidateSimultaneousTreeContract(t *testing.T) {
	for _, tc := range []struct {
		name      string
		paths     []string
		tags      []model.OperationTag
		want      error
		intrinsic bool
	}{{"intrinsic_sets", []string{"a", "a-", "a/b"}, []model.OperationTag{1, 0, 1}, metadata.ErrInvalidArgument, true},
		{"distinct_a_ab", []string{"a", "ab"}, []model.OperationTag{1, 2}, nil, false},
		{"base_a_to_directory", []string{"a", "a/b"}, []model.OperationTag{0, 1}, nil, false},
		{"base_ab_ac_to_file", []string{"a", "a/b", "a/c"}, []model.OperationTag{3, 0, 0}, nil, false},
		{"base_ab_ac_incomplete_delete", []string{"a", "a/b"}, []model.OperationTag{1, 0}, metadata.ErrFailedPrecondition, false},
		{"base_a_surviving_ancestor", []string{"a/b"}, []model.OperationTag{1}, metadata.ErrFailedPrecondition, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s, in, b := fixture()
			in.Parents = []model.ChangesetID{parentID(1), parentID(2)}
			for i, path := range tc.paths {
				in.Operations = append(in.Operations, edit(t, path, tc.tags[i]))
			}
			p := noCalls(t)
			if !tc.intrinsic {
				p.Parents = parentFake(func(c context.Context, s metadata.Scope, id model.ChangesetID) (metadata.Publication, error) {
					return publication(s, id), nil
				})
			}
			calls := 0
			p.Trees = treeFake(func(c context.Context, got metadata.Scope, tree TreeInput, tb TreeBudget) error {
				calls++
				if got != s || tree.Root || tree.FirstParent != parentID(1) || tb != b.Tree || !reflect.DeepEqual(tree.Changeset.Snapshot(), in) {
					t.Fatal("complete simultaneous delta/first parent changed")
				}
				return tc.want
			})
			v, err := Validate(context.Background(), s, in, BaseExpectation{Mode: BaseDetached}, b, p)
			if tc.want != nil {
				assertFailure(t, v, err, tc.want)
			} else if err != nil {
				t.Fatal(err)
			}
			if (tc.intrinsic && calls != 0) || (!tc.intrinsic && calls != 1) {
				t.Fatal("incorrect tree calls")
			}
		})
	}
}

// V05,V09,V10,V13: each stage stops at the first error; causes stay private.
func TestValidateDependencyFailures(t *testing.T) {
	secret := errors.New("SECRET provider alias/path/principal")
	for i, cause := range []error{metadata.ErrNotFound, metadata.ErrPermissionDenied, metadata.ErrUnauthenticated,
		metadata.ErrUnavailable, metadata.ErrFailedPrecondition, metadata.ErrResourceExhausted,
		metadata.ErrCorruptData, secret, context.DeadlineExceeded, context.Canceled, metadata.ErrDeadlineExceeded} {
		t.Run(fmt.Sprintf("cause_%d", i), func(t *testing.T) {
			providerError := fmt.Errorf("SECRET dependency diagnostic: %w", cause)
			for stage := 0; stage < 4; stage++ {
				s, in, b := fixture()
				in.Parents = []model.ChangesetID{parentID(1), parentID(2)}
				calls := 0
				p := noCalls(t)
				p.Parents = parentFake(func(c context.Context, s metadata.Scope, id model.ChangesetID) (metadata.Publication, error) {
					calls++
					if stage < 2 && calls == stage+1 {
						return metadata.Publication{}, providerError
					}
					return publication(s, id), nil
				})
				p.Aliases = aliasFake(func(context.Context, metadata.Scope, string) (metadata.RefValue, uint8, error) {
					calls++
					if stage == 2 {
						return metadata.RefValue{}, AliasAbsentState, providerError
					}
					return metadata.RefValue{}, AliasAbsentState, nil
				})
				p.Trees = treeFake(func(context.Context, metadata.Scope, TreeInput, TreeBudget) error { calls++; return providerError })
				v, err := Validate(context.Background(), s, in, BaseExpectation{Mode: BaseAliasAbsent, Alias: "a"}, b, p)
				assertFailure(t, v, err, cause)
				if !errors.Is(err, providerError) {
					t.Fatal("original provider error identity lost")
				}
				if cause == secret && !errors.Is(err, metadata.ErrUnavailable) {
					t.Fatal("unknown cause not unavailable")
				}
				if (cause == context.DeadlineExceeded || cause == metadata.ErrDeadlineExceeded) &&
					(!errors.Is(err, metadata.ErrDeadlineExceeded) || !errors.Is(err, context.DeadlineExceeded)) {
					t.Fatal("deadline mapping lost")
				}
				wantCalls := []int{1, 2, 3, 4}[stage]
				if calls != wantCalls {
					t.Fatalf("stage %d calls=%d, want %d", stage, calls, wantCalls)
				}
			}
		})
	}
}

func TestValidatePublicationBindings(t *testing.T) {
	for _, name := range []string{"repository", "changeset", "id", "event"} {
		t.Run(name, func(t *testing.T) {
			s, in, b := fixture()
			in.Parents = []model.ChangesetID{parentID(1), parentID(2)}
			p := noCalls(t)
			calls := 0
			p.Parents = parentFake(func(c context.Context, s metadata.Scope, id model.ChangesetID) (metadata.Publication, error) {
				calls++
				v := publication(s, id)
				switch name {
				case "repository":
					v.Repository[0]++
				case "changeset":
					v.Changeset = parentID(3)
				case "id":
					v.ID = ""
				case "event":
					v.Event = ""
				}
				return v, nil
			})
			v, err := Validate(context.Background(), s, in, BaseExpectation{Mode: BaseDetached}, b, p)
			assertFailure(t, v, err, metadata.ErrCorruptData)
			if calls != 1 {
				t.Fatal("continued after corrupt tuple")
			}
		})
	}
}

// V10: function types exercise typed-nil interfaces without forging model fields.
func TestValidateNilPorts(t *testing.T) {
	for _, name := range []string{"parent_nil", "parent_typed", "alias_nil", "alias_typed", "tree_nil", "tree_typed"} {
		t.Run(name, func(t *testing.T) {
			s, in, b := fixture()
			p := noCalls(t)
			base := BaseExpectation{Mode: BaseRoot}
			switch name {
			case "parent_nil", "parent_typed":
				base.Mode, in.Parents, p.Parents = BaseDetached, []model.ChangesetID{parentID(1)}, nil
				if name == "parent_typed" {
					p.Parents = parentFake(nil)
				}
			case "alias_nil", "alias_typed":
				base.Mode, base.Alias, p.Aliases = BaseAliasAbsent, "a", nil
				if name == "alias_typed" {
					p.Aliases = aliasFake(nil)
				}
			case "tree_nil":
				p.Trees = nil
			case "tree_typed":
				p.Trees = treeFake(nil)
			}
			v, err := Validate(context.Background(), s, in, base, b, p)
			assertFailure(t, v, err, metadata.ErrInvalidArgument)
		})
	}
}

// V11: small fixtures test admission; no canonical-limit/scale allocations.
func TestValidateBudgets(t *testing.T) {
	for i := 0; i < 17; i++ {
		s, in, b := fixture()
		base := BaseExpectation{Mode: BaseAliasAbsent, Alias: "aa"}
		in.Parents = []model.ChangesetID{parentID(1), parentID(2)}
		in.Operations = []model.Operation{edit(t, "a", 0), edit(t, "b", 0)}
		want := metadata.ErrInvalidArgument
		switch i {
		case 0:
			b.MaxDuration = 0
		case 1:
			b.MaxAliasBytes = 0
		case 2:
			b.MaxParents = 0
		case 3:
			b.MaxOperations = 0
		case 4:
			b.MaxPayloadBytes = 0
		case 5:
			b.MaxPayloadBytes = model.MaxChangesetPayload + 1
		case 6:
			b.MaxParents = model.MaxParents + 1
		case 7:
			b.MaxOperations = model.MaxOperations + 1
		case 8:
			b.Tree.MaxPages = 0
		case 9:
			b.Tree.MaxEntries = 0
		case 10:
			b.Tree.MaxReadBytes = 0
		case 11:
			b.Tree.MaxMemoryBytes = 0
		case 12:
			b.Tree.MaxSteps = 0
		case 13:
			b.Tree.MaxQueue = 0
		case 14:
			b.MaxPayloadBytes, want = 1, metadata.ErrResourceExhausted
		case 15:
			b.MaxParents, want = 1, metadata.ErrResourceExhausted
		case 16:
			b.MaxOperations, want = 1, metadata.ErrResourceExhausted
		}
		v, err := Validate(context.Background(), s, in, base, b, noCalls(t))
		assertFailure(t, v, err, want)
	}
	s, in, b := fixture()
	b.MaxAliasBytes = 1
	v, err := Validate(context.Background(), s, in, BaseExpectation{Mode: BaseAliasAbsent, Alias: "aa"}, b, noCalls(t))
	assertFailure(t, v, err, metadata.ErrResourceExhausted)
}

// V11,V13: cooperative waits exercise whole-call limits, never forced interruption.
func TestValidateContext(t *testing.T) {
	for _, name := range []string{"nil", "before", "parent", "alias", "tree", "tree_nil", "duration", "caller_deadline"} {
		t.Run(name, func(t *testing.T) {
			s, in, b := fixture()
			in.Parents = []model.ChangesetID{parentID(1), parentID(2)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if name == "caller_deadline" {
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer cancel()
			}
			if name == "duration" {
				b.MaxDuration = 10 * time.Millisecond
			}
			if name == "before" {
				cancel()
			}
			var seen context.Context
			original := errors.New("SECRET simultaneous cancellation/provider error")
			replyError := func(stage string) error {
				if name == stage {
					return original
				}
				return nil
			}
			calls := 0
			check := func(c context.Context, stage string) {
				calls++
				deadline, ok := c.Deadline()
				if !ok || time.Until(deadline) > b.MaxDuration {
					t.Fatal("unbounded context")
				}
				if seen != nil && seen != c {
					t.Fatal("context reset between ports")
				}
				seen = c
				if name == stage || (name == "tree_nil" && stage == "tree") {
					cancel()
				}
			}
			p := Ports{
				Parents: parentFake(func(c context.Context, s metadata.Scope, id model.ChangesetID) (metadata.Publication, error) {
					check(c, "parent")
					return publication(s, id), replyError("parent")
				}),
				Aliases: aliasFake(func(c context.Context, s metadata.Scope, name string) (metadata.RefValue, uint8, error) {
					check(c, "alias")
					return metadata.RefValue{}, AliasAbsentState, replyError("alias")
				}),
				Trees: treeFake(func(c context.Context, s metadata.Scope, in TreeInput, b TreeBudget) error {
					check(c, "tree")
					if name == "duration" || name == "caller_deadline" {
						<-c.Done()
					}
					return replyError("tree")
				}),
			}
			if name == "nil" {
				ctx = nil
			}
			v, err := Validate(ctx, s, in, BaseExpectation{Mode: BaseAliasAbsent, Alias: "a"}, b, p)
			want, count := error(context.Canceled), 4
			switch name {
			case "nil":
				want, count = metadata.ErrInvalidArgument, 0
			case "before":
				count = 0
			case "parent":
				count = 1
			case "alias":
				count = 3
			case "duration", "caller_deadline":
				want = context.DeadlineExceeded
			}
			assertFailure(t, v, err, want)
			if (name == "parent" || name == "alias" || name == "tree") && !errors.Is(err, original) {
				t.Fatal("cancellation discarded provider cause")
			}
			if calls != count {
				t.Fatalf("calls=%d, want %d", calls, count)
			}
			if want == context.DeadlineExceeded && !errors.Is(err, metadata.ErrDeadlineExceeded) {
				t.Fatal("missing metadata deadline identity")
			}
		})
	}
}

// V06,V12: admitted values survive caller and Snapshot mutations, including gen0.
func TestValidateOwnership(t *testing.T) {
	s, in, b := fixture()
	in.Parents = []model.ChangesetID{parentID(1), parentID(1), parentID(2)}
	in.Author, _ = model.NewMetadata([]byte{0xff, 0, 'x'}, -4, -1439)
	committer, _ := model.NewMetadata([]byte("committer"), math.MaxInt64, 1439)
	in.Committer, in.Message, in.Encoding = &committer, []byte("message"), []byte("encoding")
	in.Operations = []model.Operation{edit(t, "a", 1), edit(t, "b", 2), edit(t, "c", 3), edit(t, "\xff", 0)}
	want, _ := model.NewChangeset(in)
	g := uint64(0)
	base := BaseExpectation{Mode: BaseAliasPresent, Alias: "alias", ExpectedTarget: parentID(1), ExpectedGeneration: &g}
	calls := 0
	p := Ports{
		Parents: parentFake(func(c context.Context, got metadata.Scope, id model.ChangesetID) (metadata.Publication, error) {
			if got != s || id != want.Snapshot().Parents[calls] {
				t.Fatal("caller redirected parent")
			}
			calls++
			in.Parents[0] = parentID(9)
			in.Operations[0] = model.Operation{}
			in.Message[0], in.Encoding[0] = 'X', 'X'
			*in.Committer, g = model.Metadata{}, 9
			return publication(s, id), nil
		}),
		Aliases: aliasFake(func(context.Context, metadata.Scope, string) (metadata.RefValue, uint8, error) {
			return metadata.RefValue{Target: parentID(1), Generation: 0}, AliasPresentState, nil
		}),
		Trees: treeFake(func(c context.Context, got metadata.Scope, tree TreeInput, tb TreeBudget) error {
			if got != s || tree.Root || tree.FirstParent != parentID(1) || tb != b.Tree || !reflect.DeepEqual(tree.Changeset.Snapshot(), want.Snapshot()) {
				t.Fatal("owned tree input changed")
			}
			snapshot := tree.Changeset.Snapshot()
			snapshot.Parents[0] = parentID(9)
			snapshot.Operations[0] = model.Operation{}
			snapshot.Message[0], snapshot.Encoding[0] = 'X', 'X'
			*snapshot.Committer = model.Metadata{}
			return nil
		}),
	}
	v, err := Validate(context.Background(), s, in, base, b, p)
	if err != nil || !bytes.Equal(encoded(t, v), encoded(t, want)) || calls != 3 {
		t.Fatalf("ownership failed: %v", err)
	}
	hash, err := model.HashChangeset(context.Background(), v)
	wantHash, _ := model.HashChangeset(context.Background(), want)
	if err != nil || hash != wantHash {
		t.Fatal("canonical hash changed")
	}
	snapshot := v.Snapshot()
	snapshot.Parents[0] = parentID(9)
	snapshot.Operations[0] = model.Operation{}
	snapshot.Message[0], snapshot.Encoding[0] = 'X', 'X'
	*snapshot.Committer = model.Metadata{}
	if !reflect.DeepEqual(v.Snapshot(), want.Snapshot()) {
		t.Fatal("Snapshot aliases output")
	}
}

func TestValidateOptionalPresence(t *testing.T) {
	for i := 0; i < 4; i++ {
		s, in, b := fixture()
		if i&1 != 0 {
			in.Encoding = []byte{}
		}
		if i&2 != 0 {
			in.Committer = &model.Metadata{}
		}
		p := Ports{Trees: treeFake(func(context.Context, metadata.Scope, TreeInput, TreeBudget) error { return nil })}
		v, err := Validate(context.Background(), s, in, BaseExpectation{Mode: BaseRoot}, b, p)
		want, _ := model.NewChangeset(in)
		if err != nil || !reflect.DeepEqual(v.Snapshot(), in) || !bytes.Equal(encoded(t, v), encoded(t, want)) {
			t.Fatalf("presence %d changed: %v", i, err)
		}
	}
}
