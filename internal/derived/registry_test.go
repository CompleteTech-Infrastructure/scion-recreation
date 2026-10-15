package derived_test

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"canopy.local/canopy/internal/derived"
	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

func testKey(kind string, version uint32) derived.Key {
	return derived.Key{Kind: kind, Version: version}
}

func testBudget() derived.WorkBudget {
	return derived.WorkBudget{
		Steps: 1, MemoryBytes: 1, ReadBytes: 1, WriteBytes: 1,
		Objects: 1, QueueDepth: 1, Duration: time.Nanosecond,
	}
}

func testRegistration(key derived.Key) derived.Registration {
	return derived.Registration{
		Key: key,
		Output: derived.OutputType{
			CanonicalKind: model.BlobKind,
			Version:       uint32(model.CanonicalVersion),
		},
		Input:  derived.InputContract{Name: "source-parent", Version: 1},
		Budget: testBudget(),
	}
}

func requireIs(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", err, want)
	}
}

func requireRegistryError(t *testing.T, registrations []derived.Registration, want error) {
	t.Helper()
	registry, err := derived.NewRegistry(registrations)
	requireIs(t, err, want)
	if registry != nil {
		t.Fatalf("NewRegistry returned a registry with error %v", err)
	}
}

func requireZeroPlan(t *testing.T, plan derived.Plan) {
	t.Helper()
	if plan.Registrations != nil || plan.Budget != (derived.WorkBudget{}) {
		t.Fatalf("error returned non-zero plan: %+v", plan)
	}
}

func TestNewRegistryAcceptsEmptyAndVersionedArbitraryKinds(t *testing.T) {
	empty, err := derived.NewRegistry(nil)
	if err != nil || empty == nil {
		t.Fatalf("NewRegistry(nil) = (%v, %v), want non-nil registry", empty, err)
	}

	v1 := testRegistration(testKey("tree-index", 1))
	v1.Output = derived.OutputType{DerivedFormat: "TREE-v1", Version: 4}
	v1.Input = derived.InputContract{Name: "commit-parent", Version: 8}
	v2 := testRegistration(testKey("tree-index", 2))
	v2.Output = derived.OutputType{CanonicalKind: model.ChangesetKind, Version: uint32(model.CanonicalVersion)}
	v2.Input = derived.InputContract{Name: "linear-history", Version: 3}
	other := testRegistration(testKey("binary.pages", 17))
	other.Output = derived.OutputType{DerivedFormat: "opaque-v3", Version: 12}

	registry, err := derived.NewRegistry([]derived.Registration{v1, v2, other})
	if err != nil {
		t.Fatalf("NewRegistry(versioned kinds) error: %v", err)
	}
	for _, want := range []derived.Registration{v1, v2, other} {
		got, err := registry.Lookup(want.Key)
		if err != nil || got.Key != want.Key || got.Output != want.Output || got.Input != want.Input {
			t.Fatalf("Lookup(%+v) = (%+v, %v), want registration preserved", want.Key, got, err)
		}
	}
}

func TestNameGrammarAndByteLimit(t *testing.T) {
	valid := []string{"A", "a9", "A.b_c-d", strings.Repeat("x", derived.MaxNameBytes)}
	for _, name := range valid {
		if _, err := derived.NewRegistry([]derived.Registration{testRegistration(testKey(name, 1))}); err != nil {
			t.Fatalf("valid key name %q rejected: %v", name, err)
		}
	}

	invalid := []string{"", "1starts-digit", "_starts", ".starts", "-starts", "has space", "has/slash", "éclair", "a\nb", strings.Repeat("a", derived.MaxNameBytes+1)}
	for _, name := range invalid {
		requireRegistryError(t, []derived.Registration{testRegistration(testKey(name, 1))}, metadata.ErrInvalidArgument)
	}
}

func TestRegistrationValidation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*derived.Registration)
	}{
		{"zero key version", func(r *derived.Registration) { r.Key.Version = 0 }},
		{"zero input version", func(r *derived.Registration) { r.Input.Version = 0 }},
		{"invalid input name", func(r *derived.Registration) { r.Input.Name = "source/parent" }},
		{"input name byte limit", func(r *derived.Registration) { r.Input.Name = strings.Repeat("a", derived.MaxNameBytes+1) }},
		{"zero output version", func(r *derived.Registration) { r.Output.Version = 0 }},
		{"unknown canonical kind", func(r *derived.Registration) { r.Output.CanonicalKind = model.ObjectKind(3) }},
		{"canonical format must be empty", func(r *derived.Registration) { r.Output.DerivedFormat = "TREE-v1" }},
		{"canonical version must match", func(r *derived.Registration) { r.Output.Version++ }},
		{"derived format must be named", func(r *derived.Registration) { r.Output = derived.OutputType{Version: 1} }},
		{"derived format grammar", func(r *derived.Registration) { r.Output = derived.OutputType{DerivedFormat: "bad/name", Version: 1} }},
		{"derived output version required", func(r *derived.Registration) { r.Output = derived.OutputType{DerivedFormat: "TREE-v1"} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := testRegistration(testKey("valid-kind", 1))
			tt.edit(&r)
			requireRegistryError(t, []derived.Registration{r}, metadata.ErrInvalidArgument)
		})
	}
}

func TestRegistrationRejectsMalformedDependenciesAndDuplicateKeys(t *testing.T) {
	badDependency := testRegistration(testKey("root", 1))
	badDependency.Dependencies = []derived.Key{testKey("child", 0)}
	child, root := testRegistration(testKey("child", 1)), testRegistration(testKey("root", 1))
	root.Dependencies = []derived.Key{child.Key, child.Key}
	same := testRegistration(testKey("same", 1))
	changed := same
	changed.Input = derived.InputContract{Name: "different-input", Version: 1}
	cases := []struct {
		name string
		regs []derived.Registration
		want error
	}{
		{"malformed dependency key", []derived.Registration{badDependency}, metadata.ErrInvalidArgument},
		{"duplicate dependency", []derived.Registration{root, child}, metadata.ErrInvalidArgument},
		{"duplicate registration", []derived.Registration{same, same}, metadata.ErrConflict},
		{"conflicting registration", []derived.Registration{same, changed}, metadata.ErrConflict},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) { requireRegistryError(t, tt.regs, tt.want) })
	}
}

func TestMissingAndVersionedDependenciesAreUnknown(t *testing.T) {
	root := testRegistration(testKey("root", 1))
	root.Dependencies = []derived.Key{testKey("missing", 1)}
	requireRegistryError(t, []derived.Registration{root}, derived.ErrUnknownKind)
	parent := testRegistration(testKey("parent", 1))
	root.Dependencies = []derived.Key{testKey("parent", 2)}
	requireRegistryError(t, []derived.Registration{root, parent}, derived.ErrUnknownKind)
	registry, err := derived.NewRegistry(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.Lookup(testKey("missing", 1))
	requireIs(t, err, derived.ErrUnknownKind)
	plan, err := registry.Plan(testKey("missing", 1))
	requireIs(t, err, derived.ErrUnknownKind)
	requireZeroPlan(t, plan)
	registry, err = derived.NewRegistry([]derived.Registration{parent})
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.Lookup(testKey("parent", 2))
	requireIs(t, err, derived.ErrUnknownKind)
}

func TestDependencyCyclesAreReported(t *testing.T) {
	root := testRegistration(testKey("self", 1))
	root.Dependencies = []derived.Key{root.Key}
	requireRegistryError(t, []derived.Registration{root}, derived.ErrDependencyCycle)
	a, b, c := testRegistration(testKey("alpha", 1)), testRegistration(testKey("beta", 1)), testRegistration(testKey("gamma", 1))
	a.Dependencies, b.Dependencies, c.Dependencies = []derived.Key{b.Key}, []derived.Key{c.Key}, []derived.Key{a.Key}
	requireRegistryError(t, []derived.Registration{a, b, c}, derived.ErrDependencyCycle)
}

func TestPlanIsStableDependencyFirstDFSAndSumsBudgets(t *testing.T) {
	shared := testRegistration(testKey("shared", 1))
	b := testRegistration(testKey("branch-b", 1))
	a := testRegistration(testKey("branch-a", 1))
	root := testRegistration(testKey("root", 1))
	b.Dependencies = []derived.Key{shared.Key}
	a.Dependencies = []derived.Key{shared.Key}
	root.Dependencies = []derived.Key{b.Key, a.Key}
	for i, r := range []*derived.Registration{&shared, &b, &a, &root} {
		n := uint64(i + 1)
		r.Budget = derived.WorkBudget{
			Steps: n, MemoryBytes: 10 * n, ReadBytes: 100 * n,
			WriteBytes: 1000 * n, Objects: 2 * n, QueueDepth: 3 * n,
			Duration: time.Duration(n) * time.Millisecond,
		}
	}
	registry, err := derived.NewRegistry([]derived.Registration{root, a, shared, b})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	plan, err := registry.Plan(root.Key)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	wantOrder := []derived.Key{shared.Key, b.Key, a.Key, root.Key}
	if len(plan.Registrations) != len(wantOrder) {
		t.Fatalf("plan has %d registrations, want %d", len(plan.Registrations), len(wantOrder))
	}
	for i, want := range wantOrder {
		if got := plan.Registrations[i].Key; got != want {
			t.Errorf("plan registration %d = %+v, want %+v", i, got, want)
		}
	}
	wantBudget := derived.WorkBudget{
		Steps: 10, MemoryBytes: 100, ReadBytes: 1000,
		WriteBytes: 10000, Objects: 20, QueueDepth: 30,
		Duration: 10 * time.Millisecond,
	}
	if plan.Budget != wantBudget {
		t.Errorf("plan budget = %+v, want %+v", plan.Budget, wantBudget)
	}
	reversed, err := derived.NewRegistry([]derived.Registration{b, shared, a, root})
	if err != nil {
		t.Fatal(err)
	}
	reversedPlan, err := reversed.Plan(root.Key)
	if err != nil || !reflect.DeepEqual(reversedPlan, plan) {
		t.Fatalf("registration input order changed plan: (%+v, %v)", reversedPlan, err)
	}
}

func TestRegistryAndPlanOwnDependencySlices(t *testing.T) {
	child := testRegistration(testKey("child", 1))
	second := testRegistration(testKey("second", 1))
	root := testRegistration(testKey("root", 1))
	root.Dependencies = []derived.Key{child.Key}
	input := []derived.Registration{root, child, second}
	registry, err := derived.NewRegistry(input)
	if err != nil {
		t.Fatal(err)
	}

	input[0].Dependencies[0] = second.Key
	lookup, err := registry.Lookup(root.Key)
	if err != nil {
		t.Fatal(err)
	}
	lookup.Dependencies[0] = second.Key
	lookupAgain, err := registry.Lookup(root.Key)
	if err != nil || lookupAgain.Dependencies[0] != child.Key {
		t.Fatalf("Lookup dependencies aliased caller: %+v, %v", lookupAgain.Dependencies, err)
	}

	plan, err := registry.Plan(root.Key)
	if err != nil {
		t.Fatal(err)
	}
	plan.Registrations[len(plan.Registrations)-1].Dependencies[0] = second.Key
	planAgain, err := registry.Plan(root.Key)
	if err != nil || planAgain.Registrations[len(planAgain.Registrations)-1].Dependencies[0] != child.Key {
		t.Fatalf("Plan dependencies aliased registry: %+v, %v", planAgain.Registrations, err)
	}
}

func TestLookupIdentityValidatesCanonicalChangesetAndExactKey(t *testing.T) {
	var digest [32]byte
	digest[0] = 0x5a
	typed, err := model.NewTypedID(model.ChangesetKind, digest)
	if err != nil {
		t.Fatal(err)
	}
	changeset, err := model.NewChangesetID(typed)
	if err != nil {
		t.Fatal(err)
	}
	r := testRegistration(testKey("tree-index", 7))
	registry, err := derived.NewRegistry([]derived.Registration{r})
	if err != nil {
		t.Fatal(err)
	}
	identity := metadata.DerivedIdentity{Changeset: changeset, Kind: r.Key.Kind, Version: r.Key.Version}
	got, err := registry.LookupIdentity(identity)
	if err != nil || got.Key != r.Key {
		t.Fatalf("LookupIdentity(valid) = (%+v, %v)", got, err)
	}
	identity.Version++
	_, err = registry.LookupIdentity(identity)
	requireIs(t, err, derived.ErrUnknownKind)
	identity.Version = r.Key.Version
	identity.Changeset = model.ChangesetID{}
	_, err = registry.LookupIdentity(identity)
	requireIs(t, err, metadata.ErrInvalidArgument)
}

func TestBudgetValidationAndMaximumValues(t *testing.T) {
	zeroes := []struct {
		name string
		set  func(*derived.WorkBudget)
	}{
		{"steps", func(b *derived.WorkBudget) { b.Steps = 0 }},
		{"memory", func(b *derived.WorkBudget) { b.MemoryBytes = 0 }},
		{"read", func(b *derived.WorkBudget) { b.ReadBytes = 0 }},
		{"write", func(b *derived.WorkBudget) { b.WriteBytes = 0 }},
		{"objects", func(b *derived.WorkBudget) { b.Objects = 0 }},
		{"queue", func(b *derived.WorkBudget) { b.QueueDepth = 0 }},
		{"duration", func(b *derived.WorkBudget) { b.Duration = 0 }},
		{"negative duration", func(b *derived.WorkBudget) { b.Duration = -1 }},
	}
	for _, tt := range zeroes {
		t.Run("zero/"+tt.name, func(t *testing.T) {
			r := testRegistration(testKey("budget", 1))
			tt.set(&r.Budget)
			requireRegistryError(t, []derived.Registration{r}, metadata.ErrInvalidArgument)
		})
	}

	tooLarge := testRegistration(testKey("large-budget", 1))
	tooLarge.Budget.Steps = uint64(math.MaxInt64) + 1
	requireRegistryError(t, []derived.Registration{tooLarge}, metadata.ErrInvalidArgument)
	maxUint := ^uint64(0)
	for _, tt := range []struct {
		name string
		set  func(*derived.WorkBudget, uint64)
	}{
		{"steps", func(b *derived.WorkBudget, n uint64) { b.Steps = n }},
		{"memory", func(b *derived.WorkBudget, n uint64) { b.MemoryBytes = n }},
		{"read", func(b *derived.WorkBudget, n uint64) { b.ReadBytes = n }},
		{"write", func(b *derived.WorkBudget, n uint64) { b.WriteBytes = n }},
		{"objects", func(b *derived.WorkBudget, n uint64) { b.Objects = n }},
		{"queue", func(b *derived.WorkBudget, n uint64) { b.QueueDepth = n }},
	} {
		r := testRegistration(testKey("max-"+tt.name, 1))
		tt.set(&r.Budget, maxUint)
		requireRegistryError(t, []derived.Registration{r}, metadata.ErrInvalidArgument)
	}

	maximum := testRegistration(testKey("maximum-budget", 1))
	maximum.Budget = derived.WorkBudget{
		Steps: uint64(math.MaxInt64), MemoryBytes: uint64(math.MaxInt64),
		ReadBytes: uint64(math.MaxInt64), WriteBytes: uint64(math.MaxInt64),
		Objects: uint64(math.MaxInt64), QueueDepth: uint64(math.MaxInt64),
		Duration: time.Duration(math.MaxInt64),
	}
	registry, err := derived.NewRegistry([]derived.Registration{maximum})
	if err != nil {
		t.Fatalf("maximum valid budgets rejected: %v", err)
	}
	plan, err := registry.Plan(maximum.Key)
	if err != nil || plan.Budget != maximum.Budget {
		t.Fatalf("maximum single-registration plan = (%+v, %v)", plan.Budget, err)
	}
}

func TestPlanBudgetOverflowReturnsNoPartialPlan(t *testing.T) {
	fields := []struct {
		name string
		set  func(*derived.WorkBudget, int64)
	}{
		{"steps", func(b *derived.WorkBudget, n int64) { b.Steps = uint64(n) }},
		{"memory", func(b *derived.WorkBudget, n int64) { b.MemoryBytes = uint64(n) }},
		{"read", func(b *derived.WorkBudget, n int64) { b.ReadBytes = uint64(n) }},
		{"write", func(b *derived.WorkBudget, n int64) { b.WriteBytes = uint64(n) }},
		{"objects", func(b *derived.WorkBudget, n int64) { b.Objects = uint64(n) }},
		{"queue", func(b *derived.WorkBudget, n int64) { b.QueueDepth = uint64(n) }},
		{"duration", func(b *derived.WorkBudget, n int64) { b.Duration = time.Duration(n) }},
	}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			child := testRegistration(testKey("child", 1))
			root := testRegistration(testKey("root", 1))
			root.Dependencies = []derived.Key{child.Key}
			field.set(&child.Budget, math.MaxInt64)
			field.set(&root.Budget, 1)
			registry, err := derived.NewRegistry([]derived.Registration{root, child})
			if err != nil {
				t.Fatalf("valid per-registration budgets rejected: %v", err)
			}
			plan, err := registry.Plan(root.Key)
			requireIs(t, err, metadata.ErrResourceExhausted)
			requireZeroPlan(t, plan)
		})
	}
}

func TestRegistrationAndDependencyCaps(t *testing.T) {
	t.Run("registration cap", func(t *testing.T) {
		chain := make([]derived.Registration, derived.MaxRegistrations)
		for i := range chain {
			chain[i] = testRegistration(testKey(fmt.Sprintf("kind-%04d", i), 1))
			if i > 0 {
				chain[i-1].Dependencies = []derived.Key{chain[i].Key}
			}
		}
		registry, err := derived.NewRegistry(chain)
		if err != nil {
			t.Fatalf("exact registration cap rejected: %v", err)
		}
		plan, err := registry.Plan(chain[0].Key)
		if err != nil || len(plan.Registrations) != derived.MaxRegistrations {
			t.Fatalf("maximum-depth plan has %d registrations, error %v", len(plan.Registrations), err)
		}
		requireRegistryError(t, append(chain, testRegistration(testKey("kind-over", 1))), metadata.ErrResourceExhausted)
	})
	t.Run("dependency cap", func(t *testing.T) {
		root := testRegistration(testKey("root", 1))
		registrations := []derived.Registration{root}
		for i := 0; i < derived.MaxDependencies; i++ {
			child := testRegistration(testKey(fmt.Sprintf("dep-%02d", i), 1))
			root.Dependencies = append(root.Dependencies, child.Key)
			registrations = append(registrations, child)
		}
		registrations[0] = root
		if _, err := derived.NewRegistry(registrations); err != nil {
			t.Fatalf("exact dependency cap rejected: %v", err)
		}
		root.Dependencies = append(root.Dependencies, testKey("dep-over", 1))
		registrations[0] = root
		registrations = append(registrations, testRegistration(testKey("dep-over", 1)))
		requireRegistryError(t, registrations, metadata.ErrResourceExhausted)
	})
}

func TestNilRegistryReceiversRejectCalls(t *testing.T) {
	var registry *derived.Registry
	_, err := registry.Lookup(testKey("kind", 1))
	requireIs(t, err, metadata.ErrInvalidArgument)
	plan, err := registry.Plan(testKey("kind", 1))
	requireIs(t, err, metadata.ErrInvalidArgument)
	requireZeroPlan(t, plan)
	_, err = registry.LookupIdentity(metadata.DerivedIdentity{})
	requireIs(t, err, metadata.ErrInvalidArgument)
}
