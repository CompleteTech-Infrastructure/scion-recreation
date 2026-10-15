package observability

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// These independent fixture vocabularies specify every approved label value.
var testComponents = []Component{"authority", "derived", "regional_cache", "node_cache", "review", "search", "ci", "migration"}
var testOperations = []Operation{"read", "write", "query", "cache", "rebuild", "validate", "migrate"}
var testOutcomes = []Outcome{"success", "unauthenticated", "permission_denied", "not_found", "invalid_argument", "conflict", "failed_precondition", "resource_exhausted", "unavailable", "deadline_exceeded", "corrupt_data", "internal"}

func recorder(t *testing.T, capacity int) *Recorder {
	t.Helper()
	r, err := NewRecorder(capacity)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func record(t *testing.T, r *Recorder, c Component, o Operation, s Outcome, d time.Duration, id []byte) {
	t.Helper()
	if err := r.Record(c, o, s, d, id); err != nil {
		t.Fatal(err)
	}
}

func emitted(t *testing.T, r *Recorder) ([]byte, Snapshot) {
	t.Helper()
	b, err := r.ExportJSON()
	if err != nil {
		t.Fatal(err)
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return b, s
}

func contains[T comparable](domain []T, value T) bool {
	for _, v := range domain {
		if value == v {
			return true
		}
	}
	return false
}

func labels(t *testing.T, s Snapshot) {
	t.Helper()
	for _, m := range s.Metrics {
		if !contains(testComponents, m.Component) || !contains(testOperations, m.Operation) || !contains(testOutcomes, m.Outcome) {
			t.Fatalf("unapproved metric labels: %+v", m)
		}
	}
	for _, trace := range s.Traces {
		if !contains(testComponents, trace.Component) || !contains(testOperations, trace.Operation) || !contains(testOutcomes, trace.Outcome) {
			t.Fatalf("unapproved trace labels: %+v", trace)
		}
	}
	for _, h := range s.Health {
		if !contains(testComponents, h.Component) || h.State > Down {
			t.Fatalf("unapproved health: %+v", h)
		}
	}
}

func TestAllDimensionsAccounting(t *testing.T) {
	r := recorder(t, 0)
	for _, c := range testComponents {
		for _, o := range testOperations {
			for _, s := range testOutcomes {
				record(t, r, c, o, s, time.Millisecond, nil)
			}
		}
	}
	_, snap := emitted(t, r)
	labels(t, snap)
	if len(snap.Metrics) != 672 || MetricDimensions != 672 || MaxMetricSeries != 5387 {
		t.Fatalf("domain/series bound changed: %d/%d/%d", len(snap.Metrics), MetricDimensions, MaxMetricSeries)
	}
	seen := map[string]bool{}
	for _, m := range snap.Metrics {
		key := string(m.Component) + "/" + string(m.Operation) + "/" + string(m.Outcome)
		if seen[key] || m.Count != 1 || m.LatencyNanoseconds != 1000000 || m.Buckets != [6]uint64{1, 1, 1, 1, 1, 1} {
			t.Fatalf("incorrect tuple accounting: %+v", m)
		}
		seen[key] = true
	}
	if len(snap.Metrics)*8+len(snap.Health)+3 != MaxMetricSeries {
		t.Fatal("exported metric series do not match documented maximum")
	}
}

func TestLatencyBucketBoundaries(t *testing.T) {
	r := recorder(t, 32)
	for _, d := range []time.Duration{-1, 0, 1, time.Millisecond, time.Millisecond + 1, 10 * time.Millisecond, 10*time.Millisecond + 1, 100 * time.Millisecond, 100*time.Millisecond + 1, time.Second, time.Second + 1, 10 * time.Second, 10*time.Second + 1, time.Duration(1<<63 - 1)} {
		record(t, r, Authority, Read, Success, d, nil)
	}
	_, s := emitted(t, r)
	if len(s.Metrics) != 1 || s.Metrics[0].Count != 14 || s.Metrics[0].Buckets != [6]uint64{4, 6, 8, 10, 12, 14} {
		t.Fatalf("bucket boundaries: %+v", s.Metrics)
	}
	if s.Traces[0].LatencyNanoseconds != 0 || s.Traces[1].LatencyNanoseconds != 0 || s.Traces[13].LatencyNanoseconds != uint64(1<<63-1) {
		t.Fatal("latency clamping/overflow bucket lost observations")
	}
	bounds := LatencyBounds()
	bounds[0] = 0
	if LatencyBounds() != [5]time.Duration{time.Millisecond, 10 * time.Millisecond, 100 * time.Millisecond, time.Second, 10 * time.Second} {
		t.Fatal("caller mutated histogram bounds")
	}
}

func TestTraceCorrelationAndSchema(t *testing.T) {
	r := recorder(t, 4)
	id := []byte("request-00000001")
	record(t, r, Authority, Read, Success, time.Millisecond, id)
	record(t, r, NodeCache, Cache, NotFound, time.Second, id)
	record(t, r, Authority, Write, Conflict, 0, []byte("request-00000002"))
	record(t, r, CI, Validate, Success, 0, nil)
	b, s := emitted(t, r)
	labels(t, s)
	a := s.Traces[0].Correlation
	if len(a) != 32 || a != s.Traces[1].Correlation || a == s.Traces[2].Correlation || s.Traces[3].Correlation != "" {
		t.Fatal("request correlation not preserved or separated")
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Fatal(err)
	}
	other := recorder(t, 1)
	record(t, other, Authority, Read, Success, 0, id)
	if other.Snapshot().Traces[0].Correlation == a {
		t.Fatal("correlation keys shared across recorders")
	}
	if bytes.Contains(b, id) || bytes.Contains(b, []byte(hex.EncodeToString(id))) {
		t.Fatal("raw or reversibly encoded request ID emitted")
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 6 {
		t.Fatalf("unexpected top-level schema: %s", b)
	}
	var traces []map[string]json.RawMessage
	json.Unmarshal(doc["traces"], &traces)
	for i, row := range traces {
		for key := range row {
			if !contains([]string{"component", "operation", "outcome", "correlation", "latency_nanoseconds", "completed_at_unix_nano"}, key) {
				t.Fatalf("unallowlisted trace field %q", key)
			}
		}
		if s.Traces[i].CompletedAtUnixNano <= 0 {
			t.Fatal("missing completion time")
		}
	}
	var metrics []map[string]json.RawMessage
	json.Unmarshal(doc["metrics"], &metrics)
	for _, row := range metrics {
		if len(row) != 6 {
			t.Fatal("unexpected metric schema")
		}
		for key := range row {
			if !contains([]string{"component", "operation", "outcome", "count", "latency_nanoseconds", "buckets"}, key) {
				t.Fatalf("unallowlisted metric field %q", key)
			}
		}
	}
}

func TestEmittedSensitiveDataRedaction(t *testing.T) {
	r := recorder(t, 64)
	secrets := []string{"Bearer FAKE_OPS_TOKEN_6f2a", "Authorization: Basic FAKE_AUTH_9ce8", "/hidden/finance/secret-7d3b", "/private/tmp/ops-home-2f8a/.ssh/key", "/Users/fake-home-4c9e/.config/token", "distinct-user-identity-5af1", "repo-secret-39ba", "object-secret-82dc", "raw query secret-72f1", "token-16-secret!x", "/hidden/path-123", "user-00000000001"}
	for _, secret := range secrets {
		// Exercise every supported untrusted boundary, including valid 16-byte
		// correlation input. There is no arbitrary-attribute/request serializer.
		record(t, r, Authority, Query, PermissionDenied, time.Millisecond, []byte(secret))
		for _, err := range []error{r.Record(Component(secret), Read, Success, 0, nil), r.Record(Authority, Operation(secret), Success, 0, nil), r.Record(Authority, Read, Outcome(secret), 0, nil)} {
			if err != ErrInvalidDimension || strings.Contains(err.Error(), secret) {
				t.Fatal("unsafe dimension error")
			}
		}
	}
	b, s := emitted(t, r)
	labels(t, s)
	for _, secret := range secrets {
		if bytes.Contains(b, []byte(secret)) || bytes.Contains(b, []byte(hex.EncodeToString([]byte(secret)))) {
			t.Fatalf("sensitive fixture emitted: %q", secret)
		}
	}
	validIDs := 0
	for _, secret := range secrets {
		if len(secret) == 16 {
			validIDs++
		}
	}
	if validIDs == 0 || s.InvalidRequestIDs != uint64(len(secrets)-validIDs) || s.InvalidEvents != uint64(3*len(secrets)) || len(s.Traces) != len(secrets) || len(s.Metrics) != 1 || s.Metrics[0].Count != uint64(len(secrets)) {
		t.Fatalf("redaction path did not record actual events: %+v", s)
	}
	for i, trace := range s.Traces {
		if (trace.Correlation != "") != (len(secrets[i]) == 16) {
			t.Fatal("malformed IDs were retained or valid correlation lost")
		}
	}
}

func TestUniqueIDsAndPathsKeepSeriesBounded(t *testing.T) {
	r := recorder(t, 16)
	for i := 0; i < 20000; i++ {
		user := fmt.Sprintf("user-%011d", i)
		path := fmt.Sprintf("/hidden/home-%d/private", i)
		record(t, r, Search, Query, Success, 1, []byte(user))
		record(t, r, Search, Query, Success, 1, []byte(path))
		if r.Record(Component(path), Operation(user), Outcome(user), 0, nil) != ErrInvalidDimension {
			t.Fatal("unbounded dimensions accepted")
		}
	}
	b, s := emitted(t, r)
	labels(t, s)
	if len(s.Metrics) != 1 || s.Metrics[0].Count != 40000 || len(s.Traces) != 16 || s.DroppedTraces != 39984 || s.InvalidEvents != 20000 || s.InvalidRequestIDs != 20000 {
		t.Fatal("cardinality fixture accounting/capacity failed")
	}
	if len(s.Metrics)*8+len(s.Health)+3 > MaxMetricSeries {
		t.Fatal("metric series exceeded bound")
	}
	for _, secret := range []string{"user-", "/hidden/", "home-", "private"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("identifier leaked: %s", secret)
		}
	}
}

func TestInvalidDimensionsAndHealth(t *testing.T) {
	r := recorder(t, 2)
	for _, c := range testComponents {
		for _, state := range []Health{Unknown, Healthy, Degraded, Down} {
			if err := r.SetHealth(c, state); err != nil {
				t.Fatal(err)
			}
			_, s := emitted(t, r)
			for _, h := range s.Health {
				if h.Component == c && h.State != state {
					t.Fatal("health signal lost")
				}
			}
		}
	}
	if r.SetHealth(Authority, Health(255)) != ErrInvalidDimension || r.SetHealth(Component("/hidden"), Healthy) != ErrInvalidDimension {
		t.Fatal("invalid health accepted")
	}
	for _, c := range []Component{"", Component(strings.Repeat("x", 1<<20))} {
		if r.Record(c, Read, Success, 0, nil) != ErrInvalidDimension {
			t.Fatal("invalid component accepted")
		}
	}
	if r.Record(Authority, "", Success, 0, nil) != ErrInvalidDimension || r.Record(Authority, Read, "", 0, nil) != ErrInvalidDimension {
		t.Fatal("empty dimension accepted")
	}
	_, s := emitted(t, r)
	labels(t, s)
	if s.InvalidEvents != 6 || len(s.Metrics) != 0 || len(s.Traces) != 0 {
		t.Fatal("invalid dimensions mutated telemetry")
	}
	for _, h := range s.Health {
		if h.State != Down {
			t.Fatal("invalid input changed health")
		}
	}
	var zero Recorder
	if zero.Record(Authority, Read, Success, 0, nil) != ErrUninitialized || zero.SetHealth(Authority, Healthy) != ErrUninitialized {
		t.Fatal("zero recorder accepted without key")
	}
}

func TestTraceCapacityAndOverflow(t *testing.T) {
	for _, n := range []int{-1, MaxTraceCapacity + 1} {
		if r, err := NewRecorder(n); r != nil || err != ErrInvalidCapacity {
			t.Fatal("invalid capacity allocated")
		}
	}
	r := recorder(t, 3)
	for i := 0; i < 7; i++ {
		record(t, r, Authority, Read, Success, time.Duration(i), nil)
	}
	_, s := emitted(t, r)
	if s.DroppedTraces != 4 || len(s.Traces) != 3 || s.Metrics[0].Count != 7 {
		t.Fatal("ring overflow accounting")
	}
	for i, trace := range s.Traces {
		if trace.LatencyNanoseconds != uint64(i+4) {
			t.Fatal("oldest trace not overwritten")
		}
	}
	for _, n := range []int{0, MaxTraceCapacity} {
		r := recorder(t, n)
		for i := 0; i < n+1; i++ {
			record(t, r, Authority, Read, Success, 0, nil)
		}
		_, s := emitted(t, r)
		if len(s.Traces) != n || s.DroppedTraces != 1 {
			t.Fatal("boundary trace capacity")
		}
	}
}

func TestConcurrentUpdatesAndSnapshots(t *testing.T) {
	r := recorder(t, 31)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				if err := r.Record(NodeCache, Cache, Unavailable, time.Millisecond, []byte("request-00000001")); err != nil {
					t.Error(err)
				}
				if err := r.SetHealth(NodeCache, Degraded); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, s := emitted(t, r)
			labels(t, s)
			if len(s.Traces) > 31 || len(s.Metrics) > 1 {
				t.Error("concurrent snapshot exceeded bound")
			}
		}
	}()
	wg.Wait()
	_, s := emitted(t, r)
	if len(s.Metrics) != 1 || s.Metrics[0].Count != 16000 || s.Metrics[0].LatencyNanoseconds != 16000000000 || s.Metrics[0].Buckets != [6]uint64{16000, 16000, 16000, 16000, 16000, 16000} || s.DroppedTraces != 15969 {
		t.Fatalf("concurrent events lost: %+v", s.Metrics)
	}
}

func TestSnapshotIsolation(t *testing.T) {
	r := recorder(t, 1)
	record(t, r, Authority, Read, Success, 1, []byte("request-00000001"))
	r.SetHealth(Authority, Healthy)
	s := r.Snapshot()
	s.Metrics[0].Component = "secret"
	s.Metrics[0].Buckets[0] = 99
	s.Traces[0].Correlation = "secret"
	s.Health[0].State = Down
	b, after := emitted(t, r)
	if bytes.Contains(b, []byte("secret")) || after.Metrics[0].Buckets[0] != 1 || after.Health[0].State != Healthy {
		t.Fatal("snapshot aliases live state")
	}
}

func TestCounterSaturation(t *testing.T) {
	r := recorder(t, 1)
	record(t, r, Authority, Read, Success, 1, nil)
	// Seed near the representable limit, then exercise the real update/export path.
	r.mu.Lock()
	r.metrics[0].Count = ^uint64(0)
	r.metrics[0].LatencyNanoseconds = ^uint64(0) - 1
	for i := range r.metrics[0].Buckets {
		r.metrics[0].Buckets[i] = ^uint64(0)
	}
	r.dropped = ^uint64(0)
	r.invalid = ^uint64(0)
	r.invalidIDs = ^uint64(0)
	r.mu.Unlock()
	record(t, r, Authority, Read, Success, 2, []byte("malformed"))
	r.Record("bad", Read, Success, 0, nil)
	_, s := emitted(t, r)
	m := s.Metrics[0]
	if m.Count != ^uint64(0) || m.LatencyNanoseconds != ^uint64(0) || s.DroppedTraces != ^uint64(0) || s.InvalidEvents != ^uint64(0) || s.InvalidRequestIDs != ^uint64(0) {
		t.Fatal("counter wrapped")
	}
	for _, v := range m.Buckets {
		if v != ^uint64(0) {
			t.Fatal("bucket wrapped")
		}
	}
}
