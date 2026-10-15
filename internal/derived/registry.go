// Package derived describes bounded, versioned deterministic algorithms. Registry
// data is configuration, not authorization, stored results, or an evaluator.
package derived

import (
	"errors"
	"math"
	"time"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

const (
	MaxRegistrations = 1024
	MaxDependencies  = 64
	MaxNameBytes     = 64
)

var (
	ErrUnknownKind     = errors.New("unknown derived kind/version")
	ErrDependencyCycle = errors.New("derived dependency cycle")
)

// Key identifies an exact algorithm; versions never fall back or alias.
type Key struct {
	Kind    string
	Version uint32
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > MaxNameBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		letter := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
		if !letter && (i == 0 || !(c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-')) {
			return false
		}
	}
	return true
}

func (k Key) valid() bool { return validName(k.Kind) && k.Version != 0 }

// OutputType declares a format, not an ID or a new canonical object kind.
// Exactly one domain is selected: canonical v1 Blob/Changeset, or a separately
// named, versioned derived format (for example TREE v1). A derived declaration
// does not extend metadata.DerivedValueID's currently supported TREE-v1 wire ID.
type OutputType struct {
	CanonicalKind model.ObjectKind
	DerivedFormat string
	Version       uint32
}

func (o OutputType) valid() bool {
	if o.CanonicalKind != 0 {
		return o.CanonicalKind.Validate() == nil && o.DerivedFormat == "" && o.Version == uint32(model.CanonicalVersion)
	}
	return validName(o.DerivedFormat) && o.Version != 0
}

// InputContract names the versioned algorithm-specific interpretation of source
// and ordered causal inputs, including which canonical parent positions apply.
// Registry dependencies below are static algorithm prerequisites; they do not
// replace metadata.DerivedWrite's full, ordered parent identities. Evaluators
// must implement this contract and retain those identities without normalization.
type InputContract struct {
	Name    string
	Version uint32
}

// WorkBudget is an admission ceiling, not proof that an evaluator meters work.
// Steps charges CPU actions, Objects charges expanded references (including hits),
// bytes cover memory and I/O, and QueueDepth bounds admitted queued work. Every
// dimension is explicit and positive; zero never means unlimited. Duration is a
// positive wall-time ceiling. Planning sums ceilings conservatively across each
// distinct prerequisite, checking arithmetic before returning any plan.
type WorkBudget struct {
	Steps, MemoryBytes, ReadBytes, WriteBytes, Objects, QueueDepth uint64
	Duration                                                       time.Duration
}

func (b WorkBudget) valid() bool {
	for _, n := range []uint64{b.Steps, b.MemoryBytes, b.ReadBytes, b.WriteBytes, b.Objects, b.QueueDepth} {
		if n == 0 || n > math.MaxInt64 {
			return false
		}
	}
	return b.Duration > 0
}

func addBudget(a, b WorkBudget) (WorkBudget, error) {
	dst := []*uint64{&a.Steps, &a.MemoryBytes, &a.ReadBytes, &a.WriteBytes, &a.Objects, &a.QueueDepth}
	for i, n := range []uint64{b.Steps, b.MemoryBytes, b.ReadBytes, b.WriteBytes, b.Objects, b.QueueDepth} {
		if n > math.MaxInt64-*dst[i] {
			return WorkBudget{}, metadata.ErrResourceExhausted
		}
		*dst[i] += n
	}
	if b.Duration > time.Duration(math.MaxInt64)-a.Duration {
		return WorkBudget{}, metadata.ErrResourceExhausted
	}
	a.Duration += b.Duration
	return a, nil
}

type Registration struct {
	Key          Key
	Dependencies []Key // exact versions, in algorithm-declared order
	Output       OutputType
	Input        InputContract
	Budget       WorkBudget
}

func clone(r Registration) Registration {
	r.Dependencies = append([]Key(nil), r.Dependencies...)
	return r
}

// Registry is an immutable snapshot. Concurrent reads need no global sequencer,
// and it holds no runtime results/cache. Use NewRegistry; do not copy while
// constructing configuration or concurrently mutate caller-owned input slices.
type Registry struct{ entries map[Key]Registration }

// NewRegistry registers an entire configuration atomically, allowing forward
// references within the batch. On any error there is no partial registry. Even
// identical duplicate keys conflict: existing definitions cannot be rebound.
func NewRegistry(registrations []Registration) (*Registry, error) {
	if len(registrations) > MaxRegistrations {
		return nil, metadata.ErrResourceExhausted
	}
	r := &Registry{entries: make(map[Key]Registration, len(registrations))}
	roots := make([]Key, 0, len(registrations))
	for _, item := range registrations {
		if len(item.Dependencies) > MaxDependencies {
			return nil, metadata.ErrResourceExhausted
		}
		if !item.Key.valid() || !item.Output.valid() || !validName(item.Input.Name) || item.Input.Version == 0 || !item.Budget.valid() {
			return nil, metadata.ErrInvalidArgument
		}
		if _, exists := r.entries[item.Key]; exists {
			return nil, metadata.ErrConflict
		}
		seen := make(map[Key]bool, len(item.Dependencies))
		for _, dep := range item.Dependencies {
			if !dep.valid() || seen[dep] {
				return nil, metadata.ErrInvalidArgument
			}
			seen[dep] = true
		}
		r.entries[item.Key] = clone(item)
		roots = append(roots, item.Key)
	}
	if _, err := r.order(roots); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Registry) Lookup(key Key) (Registration, error) {
	if r == nil || !key.valid() {
		return Registration{}, metadata.ErrInvalidArgument
	}
	item, ok := r.entries[key]
	if !ok {
		return Registration{}, ErrUnknownKind
	}
	return clone(item), nil
}

// LookupIdentity validates the accepted metadata key's canonical ChangesetID and
// selects its exact kind/version. It performs no publication or permission check
// and never removes repository/source identity from any stored result.
func (r *Registry) LookupIdentity(id metadata.DerivedIdentity) (Registration, error) {
	if id.Validate() != nil {
		return Registration{}, metadata.ErrInvalidArgument
	}
	return r.Lookup(Key{Kind: id.Kind, Version: id.Version})
}

// order uses explicit bounded DFS frames. It preserves declared dependency order
// for ties and emits each prerequisite once before its consumer, independent of
// map iteration or registration order. Active nodes detect even indirect cycles.
func (r *Registry) order(roots []Key) ([]Key, error) {
	type frame struct {
		key  Key
		next int
	}
	state := make(map[Key]uint8, len(r.entries))
	order := make([]Key, 0, len(r.entries))
	stack := make([]frame, 0, len(r.entries))
	for _, root := range roots {
		if state[root] == 2 {
			continue
		}
		stack = append(stack, frame{key: root})
		state[root] = 1
		for len(stack) > 0 {
			top := &stack[len(stack)-1]
			item, ok := r.entries[top.key]
			if !ok {
				return nil, ErrUnknownKind
			}
			if top.next == len(item.Dependencies) {
				state[top.key] = 2
				order = append(order, top.key)
				stack = stack[:len(stack)-1]
				continue
			}
			dep := item.Dependencies[top.next]
			top.next++
			switch state[dep] {
			case 1:
				return nil, ErrDependencyCycle
			case 0:
				state[dep] = 1
				stack = append(stack, frame{key: dep})
			}
		}
	}
	return order, nil
}

type Plan struct {
	Registrations []Registration
	Budget        WorkBudget
}

// Plan returns dependency-first configuration and its checked admission budget.
// Actual work scheduling, causal parent lookup, authorization and metering belong
// to the evaluator and metadata port; a plan is not permission to deliver objects.
func (r *Registry) Plan(key Key) (Plan, error) {
	if _, err := r.Lookup(key); err != nil {
		return Plan{}, err
	}
	keys, err := r.order([]Key{key})
	if err != nil {
		return Plan{}, err
	}
	var plan Plan
	for _, k := range keys {
		item := r.entries[k]
		plan.Budget, err = addBudget(plan.Budget, item.Budget)
		if err != nil {
			return Plan{}, err
		}
		plan.Registrations = append(plan.Registrations, clone(item))
	}
	return plan, nil
}
