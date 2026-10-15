// Package observability provides bounded, in-process telemetry for later component
// adoption. It installs no exporters, endpoints, alerts or remediation actions.
package observability

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Dimensions are closed vocabularies, not service wire APIs. Casts from arbitrary
// strings are rejected before recording; identifiers and attributes are not labels.
type Component string
type Operation string
type Outcome string

const (
	Authority     Component = "authority"
	Derived       Component = "derived"
	RegionalCache Component = "regional_cache"
	NodeCache     Component = "node_cache"
	Review        Component = "review"
	Search        Component = "search"
	CI            Component = "ci"
	Migration     Component = "migration"

	Read     Operation = "read"
	Write    Operation = "write"
	Query    Operation = "query"
	Cache    Operation = "cache"
	Rebuild  Operation = "rebuild"
	Validate Operation = "validate"
	Migrate  Operation = "migrate"

	Success            Outcome = "success"
	Unauthenticated    Outcome = "unauthenticated"
	PermissionDenied   Outcome = "permission_denied"
	NotFound           Outcome = "not_found"
	InvalidArgument    Outcome = "invalid_argument"
	Conflict           Outcome = "conflict"
	FailedPrecondition Outcome = "failed_precondition"
	ResourceExhausted  Outcome = "resource_exhausted"
	Unavailable        Outcome = "unavailable"
	DeadlineExceeded   Outcome = "deadline_exceeded"
	CorruptData        Outcome = "corrupt_data"
	Internal           Outcome = "internal"
)

var components = [...]Component{Authority, Derived, RegionalCache, NodeCache, Review, Search, CI, Migration}
var operations = [...]Operation{Read, Write, Query, Cache, Rebuild, Validate, Migrate}
var outcomes = [...]Outcome{Success, Unauthenticated, PermissionDenied, NotFound, InvalidArgument, Conflict, FailedPrecondition, ResourceExhausted, Unavailable, DeadlineExceeded, CorruptData, Internal}

const (
	ComponentCount     = 8
	OperationCount     = 7
	OutcomeCount       = 12
	MetricDimensions   = ComponentCount * OperationCount * OutcomeCount // 672 tuples
	LatencyBucketCount = 6                                              // five finite upper bounds plus an overflow bucket
	MaxTraceCapacity   = 1024
	// Count, sum and six cumulative buckets per tuple; one health gauge per
	// component; three unlabeled diagnostic counters. No other series exist.
	MaxMetricSeries = MetricDimensions*(LatencyBucketCount+2) + ComponentCount + 3 // 5387
)

// LatencyBounds returns a copy. The final bucket has no finite upper bound.
func LatencyBounds() [LatencyBucketCount - 1]time.Duration {
	return [...]time.Duration{time.Millisecond, 10 * time.Millisecond, 100 * time.Millisecond, time.Second, 10 * time.Second}
}

type Health uint8

const (
	Unknown Health = iota
	Healthy
	Degraded
	Down
)

var (
	ErrInvalidDimension = errors.New("telemetry: invalid dimension")
	ErrInvalidCapacity  = errors.New("telemetry: invalid trace capacity")
	ErrUninitialized    = errors.New("telemetry: recorder requires NewRecorder")
)

// Metric contains only three finite labels. Buckets are cumulative inclusive
// counts in LatencyBounds order, followed by the all-observations bucket.
type Metric struct {
	Component          Component                  `json:"component"`
	Operation          Operation                  `json:"operation"`
	Outcome            Outcome                    `json:"outcome"`
	Count              uint64                     `json:"count"`
	LatencyNanoseconds uint64                     `json:"latency_nanoseconds"`
	Buckets            [LatencyBucketCount]uint64 `json:"buckets"`
}

// Trace is an allowlisted completion event, never a serialized request. Correlation
// is a recorder-local keyed digest of exactly 16 request-ID bytes, not a raw ID or
// metric label. Share a recorder across components to correlate their events.
type Trace struct {
	Component           Component `json:"component"`
	Operation           Operation `json:"operation"`
	Outcome             Outcome   `json:"outcome"`
	Correlation         string    `json:"correlation,omitempty"`
	LatencyNanoseconds  uint64    `json:"latency_nanoseconds"`
	CompletedAtUnixNano int64     `json:"completed_at_unix_nano"`
}

type ComponentHealth struct {
	Component Component `json:"component"`
	State     Health    `json:"state"`
}

type Snapshot struct {
	Metrics           []Metric                        `json:"metrics"`
	Health            [ComponentCount]ComponentHealth `json:"health"`
	Traces            []Trace                         `json:"traces"`
	DroppedTraces     uint64                          `json:"dropped_traces"`
	InvalidEvents     uint64                          `json:"invalid_events"`
	InvalidRequestIDs uint64                          `json:"invalid_request_ids"`
}

// Recorder is safe for concurrent use and must not be copied. Storage is fixed
// at construction: 672 metric tuples, eight health values and <=1024 traces.
// Record does bounded work (including <=16 input bytes), performs no I/O, and
// starts no goroutines. A short mutex protects only this recorder, not repository
// operations. Snapshots copy bounded state; consumers control their own retention.
type Recorder struct {
	mu                           sync.Mutex
	ready                        bool
	key                          [32]byte
	metrics                      [MetricDimensions]Metric
	health                       [ComponentCount]Health
	traces                       []Trace
	next, size                   int
	dropped, invalid, invalidIDs uint64
}

// NewRecorder rejects out-of-range capacities without allocating. Zero disables
// trace retention while keeping metrics; each unretained event counts as dropped.
// A full ring overwrites the oldest trace. Counters and latency sums saturate at
// uint64's maximum instead of wrapping. Negative durations are clamped to zero.
func NewRecorder(traceCapacity int) (*Recorder, error) {
	if traceCapacity < 0 || traceCapacity > MaxTraceCapacity {
		return nil, ErrInvalidCapacity
	}
	r := &Recorder{traces: make([]Trace, traceCapacity)}
	if _, err := rand.Read(r.key[:]); err != nil {
		return nil, errors.New("telemetry: correlation key unavailable")
	}
	r.ready = true
	return r, nil
}

func index[T ~string](value T, domain []T) int {
	// Check length before comparisons, bounding work even for huge hostile input.
	if len(value) > 24 {
		return -1
	}
	for i, allowed := range domain {
		if value == allowed {
			return i
		}
	}
	return -1
}

func add(a, b uint64) uint64 {
	if ^uint64(0)-a < b {
		return ^uint64(0)
	}
	return a + b
}

// Record records one completed operation. Request IDs are optional correlation
// input only: nil/empty means absent, nonempty lengths other than 16 are omitted
// and counted. Raw bytes are never retained, logged or returned, even on error.
// Callers must not attach paths, users, authorization or error text: the API has
// no such fields. Unknown dimensions fail with a constant error and no trace.
func (r *Recorder) Record(component Component, operation Operation, outcome Outcome, latency time.Duration, requestID []byte) error {
	c, o, s := index(component, components[:]), index(operation, operations[:]), index(outcome, outcomes[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ready {
		return ErrUninitialized
	}
	if c < 0 || o < 0 || s < 0 {
		r.invalid = add(r.invalid, 1)
		return ErrInvalidDimension
	}
	if latency < 0 {
		latency = 0
	}
	correlation := ""
	if len(requestID) == 16 {
		h := hmac.New(sha256.New, r.key[:])
		h.Write(requestID)
		correlation = hex.EncodeToString(h.Sum(nil)[:16])
	} else if len(requestID) != 0 {
		r.invalidIDs = add(r.invalidIDs, 1)
	}
	m := &r.metrics[(c*OperationCount+o)*OutcomeCount+s]
	m.Component, m.Operation, m.Outcome = components[c], operations[o], outcomes[s]
	m.Count = add(m.Count, 1)
	m.LatencyNanoseconds = add(m.LatencyNanoseconds, uint64(latency))
	for i, bound := range LatencyBounds() {
		if latency <= bound {
			m.Buckets[i] = add(m.Buckets[i], 1)
		}
	}
	m.Buckets[LatencyBucketCount-1] = add(m.Buckets[LatencyBucketCount-1], 1)
	if r.size == len(r.traces) {
		r.dropped = add(r.dropped, 1)
	}
	if len(r.traces) > 0 {
		r.traces[r.next] = Trace{components[c], operations[o], outcomes[s], correlation, uint64(latency), time.Now().UnixNano()}
		r.next = (r.next + 1) % len(r.traces)
		if r.size < len(r.traces) {
			r.size++
		}
	}
	return nil
}

// SetHealth records a caller-observed signal, not an autonomous diagnosis. It
// authorizes no remediation. Unknown is the initial state; invalid input fails.
func (r *Recorder) SetHealth(component Component, state Health) error {
	c := index(component, components[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ready {
		return ErrUninitialized
	}
	if c < 0 || state > Down {
		r.invalid = add(r.invalid, 1)
		return ErrInvalidDimension
	}
	r.health[c] = state
	return nil
}

// Snapshot returns an independent, read-only-by-convention copy, with metrics in
// fixed domain order and retained traces oldest first. It exposes no key/raw IDs.
func (r *Recorder) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Snapshot{Metrics: make([]Metric, 0, MetricDimensions), Traces: make([]Trace, r.size), DroppedTraces: r.dropped, InvalidEvents: r.invalid, InvalidRequestIDs: r.invalidIDs}
	for _, m := range r.metrics {
		if m.Count != 0 {
			s.Metrics = append(s.Metrics, m)
		}
	}
	for i, c := range components {
		s.Health[i] = ComponentHealth{c, r.health[i]}
	}
	if r.size != 0 {
		for i := range s.Traces {
			s.Traces[i] = r.traces[(r.next-r.size+len(r.traces)+i)%len(r.traces)]
		}
	}
	return s
}

// ExportJSON emits only the sanitized snapshot schema. Access control and secure
// transport/storage for telemetry readers belong to the eventual adopting service.
func (r *Recorder) ExportJSON() ([]byte, error) { return json.Marshal(r.Snapshot()) }
