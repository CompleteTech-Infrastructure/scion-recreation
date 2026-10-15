package authz

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"canopy.local/canopy/internal/model"
)

func admissionTestNew(t *testing.T, change func(*AdmissionLimits)) *Admission {
	t.Helper()
	limits := DefaultAdmissionLimits()
	if change != nil {
		change(&limits)
	}
	a, err := NewAdmission(limits)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func admissionTestAcquire(t *testing.T, a *Admission, principal PrincipalID) *AdmissionPermit {
	t.Helper()
	p, err := a.Acquire(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func admissionTestPrincipal(issuer, subject string, class PrincipalClass) PrincipalID {
	return PrincipalID{Issuer: issuer, Subject: subject, Class: class}
}

type admissionCountReader struct {
	reader  io.Reader
	calls   int
	bytes   int
	largest int
}

func (r *admissionCountReader) Read(p []byte) (int, error) {
	r.calls++
	if len(p) > r.largest {
		r.largest = len(p)
	}
	n, err := r.reader.Read(p)
	r.bytes += n
	return n, err
}

type admissionFailReader struct{ err error }

func (r admissionFailReader) Read([]byte) (int, error) { return 0, r.err }

type admissionCancelReader struct {
	cancel context.CancelFunc
	data   []byte
	done   bool
}

func (r *admissionCancelReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	n := copy(p, r.data)
	r.cancel()
	return n, nil
}

type admissionFailWriter struct{ err error }

func (w admissionFailWriter) Write([]byte) (int, error) { return 0, w.err }

type admissionBlockingWriter struct {
	entered chan struct{}
	resume  <-chan struct{}
	once    sync.Once
}

func (w *admissionBlockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.resume
	return len(p), nil
}

func admissionTestFrame(payload []byte) []byte {
	frame := make([]byte, 22+len(payload))
	for i := 0; i < 22; i++ {
		frame[i] = byte(i + 1)
	}
	copy(frame[22:], payload)
	return frame
}

func admissionTestGZIP(t *testing.T, frame []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(frame); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), b.Bytes()...)
}

func admissionWaitQueued(t *testing.T, a *Admission, count uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for a.Stats().Queued != count {
		if time.Now().After(deadline) {
			t.Fatalf("queue did not reach %d: %+v", count, a.Stats())
		}
		runtime.Gosched()
	}
}

type admissionAcquireResult struct {
	permit *AdmissionPermit
	err    error
}

func admissionStartWaiter(a *Admission, ctx context.Context, principal PrincipalID) <-chan admissionAcquireResult {
	result := make(chan admissionAcquireResult, 1)
	go func() {
		p, err := a.Acquire(ctx, principal)
		result <- admissionAcquireResult{p, err}
	}()
	return result
}

func TestAdmissionRequestBounds(t *testing.T) {
	a := admissionTestNew(t, nil)
	limits := DefaultAdmissionLimits()
	contract := []struct {
		resource AdmissionResource
		value    uint64
	}{
		{AdmissionReadRequestBytes, 2 << 20}, {AdmissionUploadRequestBytes, 8 << 20},
		{AdmissionResponseBytes, 16 << 20}, {AdmissionDepth, 16},
		{AdmissionWholeFrameBytes, 64<<20 + 22}, {AdmissionWholeEncodedBytes, 68 << 20},
		{AdmissionStreamBytes, 128 << 20}, {AdmissionChunkBytes, 4 << 20},
		{AdmissionWantedObjects, 128}, {AdmissionStreamFrames, 8192},
		{AdmissionMetadataBytes, 16384}, {AdmissionGrantBytes, 8192},
		{AdmissionGrantTokenBytes, 4096}, {AdmissionResumeTokenBytes, 4096},
		{AdmissionAudienceBytes, 256}, {AdmissionKeyIDBytes, 64},
		{AdmissionRangeChunks, 64}, {AdmissionProofBytes, 65536},
		{AdmissionProofSiblings, 64}, {AdmissionRetries, 3},
		{AdmissionDeadlineMillis, 30000}, {AdmissionExpansionRatio, 64},
		{AdmissionDecoderWindowBytes, 8 << 20}, {AdmissionSessionMillis, 3600000},
		{AdmissionResolvedProofBytes, 1 << 20}, {AdmissionIntervals, 64},
		{AdmissionStateBytes, 2 << 20}, {AdmissionCompletionRecords, 128},
		{AdmissionRetainedSessions, 8}, {AdmissionLogicalBytes, 1 << 40},
		{AdmissionWork, 16777216}, {AdmissionPolicyRules, 65536},
		{AdmissionVisits, 1048576}, {AdmissionTraversalDepth, 4096},
		{AdmissionStagingBytes, (1 << 40) + 22}, {AdmissionChunkAttempts, 1048580},
		{AdmissionDistinctChunks, 262145},
		{AdmissionInputBytes, (1 << 40) + 22}, {AdmissionDecodedBytes, (1 << 40) + 22},
		{AdmissionEnvelopeBytes, 1024}, {AdmissionUploadIngressBytes, 4 * ((1 << 40) + 22)},
		{AdmissionParents, 1024}, {AdmissionOperations, 1000000},
		{AdmissionPathBytes, 65535}, {AdmissionPathComponents, 1024},
		{AdmissionIdentityBytes, 65536}, {AdmissionMessageBytes, 16 << 20},
		{AdmissionEncodingBytes, 256},
	}
	for _, tc := range contract {
		if got := limits.Bounds[tc.resource]; got != tc.value {
			t.Errorf("resource %d bound = %d, want %d", tc.resource, got, tc.value)
		}
		if err := a.Check(tc.resource, tc.value); err != nil {
			t.Errorf("resource %d rejected exact cap: %v", tc.resource, err)
		}
		if err := a.Check(tc.resource, tc.value+1); !errors.Is(err, ErrAdmissionLimit) {
			t.Errorf("resource %d accepted cap+1: %v", tc.resource, err)
		}
	}
	for _, tc := range []struct {
		kind  AdmissionRequestKind
		bytes uint64
	}{
		{AdmissionReadRequest, 2 << 20}, {AdmissionBeginRequest, 2 << 20},
		{AdmissionUploadRequest, 8 << 20}, {AdmissionResponse, 16 << 20},
	} {
		if err := a.CheckRequest(tc.kind, tc.bytes, 16, false); err != nil {
			t.Errorf("request kind %d rejected exact cap: %v", tc.kind, err)
		}
		if err := a.CheckRequest(tc.kind, tc.bytes+1, 16, false); !errors.Is(err, ErrAdmissionLimit) {
			t.Errorf("request kind %d accepted cap+1: %v", tc.kind, err)
		}
	}
	if err := a.CheckRequest(AdmissionReadRequest, 1, 17, false); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("accepted excessive nesting depth: %v", err)
	}
	if err := a.CheckRequest(AdmissionReadRequest, 1, 1, true); !errors.Is(err, ErrAdmissionInvalid) {
		t.Fatalf("accepted compressed authorization request: %v", err)
	}
	if err := a.CheckRequest(99, 1, 1, false); !errors.Is(err, ErrAdmissionInvalid) {
		t.Fatalf("accepted unknown request kind: %v", err)
	}
	if err := a.Check(AdmissionResourceCount, 0); !errors.Is(err, ErrAdmissionInvalid) {
		t.Fatalf("accepted unknown resource: %v", err)
	}
	if err := a.Check(AdmissionInputBytes, ^uint64(0)); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("accepted overflowing input length: %v", err)
	}

	short := admissionTestNew(t, func(l *AdmissionLimits) {
		l.Bounds[AdmissionReadRequestBytes] = 8
		l.Bounds[AdmissionDepth] = 2
	})
	tooLarge := &admissionCountReader{reader: bytes.NewReader([]byte("x"))}
	var untouched bytes.Buffer
	p := admissionTestAcquire(t, short, admissionTestPrincipal("issuer", "request", Human))
	if n, err := p.CopyRequest(context.Background(), &untouched, tooLarge, AdmissionReadRequest, 9, 1, false); n != 0 || !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("oversized declared request copied: n=%d err=%v", n, err)
	}
	if tooLarge.calls != 0 || untouched.Len() != 0 || short.Stats().Active != 0 {
		t.Fatal("declared request rejection performed I/O or retained its permit")
	}
	actual := &admissionCountReader{reader: bytes.NewReader([]byte("12345"))}
	var copied bytes.Buffer
	p = admissionTestAcquire(t, short, admissionTestPrincipal("issuer", "request", Human))
	if n, err := p.CopyRequest(context.Background(), &copied, actual, AdmissionReadRequest, 4, 2, false); n != 4 || !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("actual request overflow: n=%d err=%v", n, err)
	}
	if actual.bytes != 5 || copied.String() != "1234" || short.Stats().Active != 0 {
		t.Fatal("request overflow was not bounded to declared bytes plus one")
	}
	underflow := &admissionCountReader{reader: bytes.NewReader([]byte("123"))}
	copied.Reset()
	p = admissionTestAcquire(t, short, admissionTestPrincipal("issuer", "request", Human))
	if n, err := p.CopyRequest(context.Background(), &copied, underflow, AdmissionReadRequest, 4, 2, false); n != 3 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short request: n=%d err=%v", n, err)
	}
	if short.Stats().Active != 0 {
		t.Fatal("short request retained its permit")
	}
}

func TestAdmissionObjectDeclaredAndActualBounds(t *testing.T) {
	short := admissionTestNew(t, func(l *AdmissionLimits) {
		l.Bounds[AdmissionDecodedBytes] = 64
		l.Bounds[AdmissionInputBytes] = 64
		l.Bounds[AdmissionLogicalBytes] = 32
		l.Bounds[AdmissionWholeFrameBytes] = 64
		l.Bounds[AdmissionWholeEncodedBytes] = 64
	})
	frame := admissionTestFrame([]byte("four"))
	reader := &admissionCountReader{reader: bytes.NewReader(frame)}
	var out bytes.Buffer
	p := admissionTestAcquire(t, short, admissionTestPrincipal("issuer", "object", Human))
	n, err := p.CopyObject(context.Background(), &out, reader, AdmissionObject{model.BlobKind, 4, uint64(len(frame)), AdmissionRaw, true})
	if err != nil || n != uint64(len(frame)) || !bytes.Equal(out.Bytes(), frame) {
		t.Fatalf("bounded object copy: n=%d err=%v", n, err)
	}
	if reader.largest > 32768 || short.Stats().Active != 0 {
		t.Fatal("copy allocated an object-sized read or retained its permit")
	}
	oversized := &admissionCountReader{reader: bytes.NewReader(frame)}
	out.Reset()
	p = admissionTestAcquire(t, short, admissionTestPrincipal("issuer", "object", Human))
	if n, err := p.CopyObject(context.Background(), &out, oversized, AdmissionObject{model.BlobKind, 43, 65, AdmissionRaw, true}); n != 0 || !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("oversized declaration: n=%d err=%v", n, err)
	}
	if oversized.calls != 0 || out.Len() != 0 || short.Stats().Active != 0 {
		t.Fatal("oversized object was read, written, or left reserved")
	}
	extra := append(append([]byte(nil), frame...), 0xee)
	actual := &admissionCountReader{reader: bytes.NewReader(extra)}
	out.Reset()
	p = admissionTestAcquire(t, short, admissionTestPrincipal("issuer", "object", Human))
	if n, err := p.CopyObject(context.Background(), &out, actual, AdmissionObject{model.BlobKind, 4, uint64(len(frame)), AdmissionRaw, true}); n != uint64(len(frame)) || !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("actual object overflow: n=%d err=%v", n, err)
	}
	if actual.bytes != len(frame)+1 || out.Len() != len(frame) || short.Stats().Active != 0 {
		t.Fatal("actual object overflow read beyond one sentinel or retained its permit")
	}
	actual = &admissionCountReader{reader: bytes.NewReader(frame[:len(frame)-1])}
	out.Reset()
	p = admissionTestAcquire(t, short, admissionTestPrincipal("issuer", "object", Human))
	if n, err := p.CopyObject(context.Background(), &out, actual, AdmissionObject{model.BlobKind, 4, uint64(len(frame)), AdmissionRaw, true}); n != uint64(len(frame)-1) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short object: n=%d err=%v", n, err)
	}
	if short.Stats().Active != 0 {
		t.Fatal("short object retained its permit")
	}
	wrongInput := &admissionCountReader{reader: bytes.NewReader(frame)}
	p = admissionTestAcquire(t, short, admissionTestPrincipal("issuer", "object", Human))
	if n, err := p.CopyObject(context.Background(), io.Discard, wrongInput, AdmissionObject{model.BlobKind, 4, uint64(len(frame) - 1), AdmissionRaw, true}); n != 0 || !errors.Is(err, ErrAdmissionInvalid) {
		t.Fatalf("inconsistent raw input declaration: n=%d err=%v", n, err)
	}
	if wrongInput.calls != 0 || short.Stats().Active != 0 {
		t.Fatal("inconsistent declaration consumed input or retained its permit")
	}
	tooLargeChangeset := &admissionCountReader{reader: admissionFailReader{io.ErrClosedPipe}}
	p = admissionTestAcquire(t, short, admissionTestPrincipal("issuer", "changeset", Human))
	if _, err := p.CopyObject(context.Background(), io.Discard, tooLargeChangeset, AdmissionObject{model.ChangesetKind, 64<<20 + 1, 64<<20 + 23, AdmissionRaw, false}); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("oversized changeset declaration: %v", err)
	}
	if tooLargeChangeset.calls != 0 || short.Stats().Active != 0 {
		t.Fatal("oversized changeset declaration reached input")
	}

	// The accepted maximum declarations are checked using immediate-error
	// readers, so the 64 MiB and 1 TiB boundaries never allocate those objects.
	whole := admissionTestNew(t, nil)
	stop := errors.New("stop after bounded first read")
	largeWhole := &admissionCountReader{reader: admissionFailReader{stop}}
	p = admissionTestAcquire(t, whole, admissionTestPrincipal("issuer", "large", Human))
	if _, err := p.CopyObject(context.Background(), io.Discard, largeWhole, AdmissionObject{model.ChangesetKind, 64 << 20, 64<<20 + 22, AdmissionRaw, true}); !errors.Is(err, stop) {
		t.Fatalf("maximum whole-object declaration was rejected before I/O: %v", err)
	}
	if largeWhole.largest > 32768 || whole.Stats().Active != 0 {
		t.Fatal("whole-object boundary allocated a large buffer or retained its permit")
	}
	largeUpload := &admissionCountReader{reader: admissionFailReader{stop}}
	p = admissionTestAcquire(t, whole, admissionTestPrincipal("issuer", "upload", Human))
	if _, err := p.CopyObject(context.Background(), io.Discard, largeUpload, AdmissionObject{model.BlobKind, 1 << 40, (1 << 40) + 22, AdmissionRaw, false}); !errors.Is(err, stop) {
		t.Fatalf("maximum blob upload declaration was rejected before I/O: %v", err)
	}
	if largeUpload.largest > 32768 || whole.Stats().Active != 0 {
		t.Fatal("large upload boundary allocated a large buffer or retained its permit")
	}
}

func TestAdmissionGZIPExpansionAndFraming(t *testing.T) {
	a := admissionTestNew(t, func(l *AdmissionLimits) {
		l.Bounds[AdmissionDecodedBytes] = 32768
		l.Bounds[AdmissionInputBytes] = 1024
		l.Bounds[AdmissionLogicalBytes] = 16384
		l.Bounds[AdmissionWholeFrameBytes] = 32768
		l.Bounds[AdmissionWholeEncodedBytes] = 1024
		l.Bounds[AdmissionDecoderWindowBytes] = 32768
	})
	frame := admissionTestFrame([]byte("a modest compressed payload"))
	compressed := admissionTestGZIP(t, frame)
	reader := &admissionCountReader{reader: bytes.NewReader(compressed)}
	var out bytes.Buffer
	p := admissionTestAcquire(t, a, admissionTestPrincipal("issuer", "gzip", Human))
	n, err := p.CopyObject(context.Background(), &out, reader, AdmissionObject{model.BlobKind, uint64(len(frame) - 22), uint64(len(compressed)), AdmissionGZIP, true})
	if err != nil || n != uint64(len(frame)) || !bytes.Equal(out.Bytes(), frame) {
		t.Fatalf("valid single-member GZIP: n=%d err=%v", n, err)
	}

	bombFrame := admissionTestFrame(bytes.Repeat([]byte{'z'}, 16384))
	bomb := admissionTestGZIP(t, bombFrame)
	if uint64(len(bomb))*64 >= uint64(len(bombFrame)) {
		t.Fatal("fixture does not exceed the independent 64:1 ratio")
	}
	untouched := &admissionCountReader{reader: bytes.NewReader(bomb)}
	out.Reset()
	p = admissionTestAcquire(t, a, admissionTestPrincipal("issuer", "bomb", Human))
	if n, err := p.CopyObject(context.Background(), &out, untouched, AdmissionObject{model.BlobKind, 16384, uint64(len(bomb)), AdmissionGZIP, true}); n != 0 || !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("decompression bomb preflight: n=%d err=%v", n, err)
	}
	if untouched.calls != 0 || out.Len() != 0 || a.Stats().Active != 0 {
		t.Fatal("decompression ratio rejection performed I/O or retained its permit")
	}
	badCodec := &admissionCountReader{reader: bytes.NewReader(frame)}
	p = admissionTestAcquire(t, a, admissionTestPrincipal("issuer", "codec", Human))
	if _, err := p.CopyObject(context.Background(), io.Discard, badCodec, AdmissionObject{model.BlobKind, uint64(len(frame) - 22), uint64(len(frame)), 99, true}); !errors.Is(err, ErrAdmissionInvalid) {
		t.Fatalf("unknown codec: %v", err)
	}
	if badCodec.calls != 0 {
		t.Fatal("unknown codec consumed input")
	}
	actualLong := admissionTestGZIP(t, admissionTestFrame([]byte("actual payload is longer")))
	p = admissionTestAcquire(t, a, admissionTestPrincipal("issuer", "gzip-long", Human))
	if n, err := p.CopyObject(context.Background(), io.Discard, bytes.NewReader(actualLong), AdmissionObject{model.BlobKind, 1, uint64(len(actualLong)), AdmissionGZIP, true}); n != 0 || !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("actual decompressed size exceeded declared payload: n=%d err=%v", n, err)
	}
	corrupt := append([]byte(nil), compressed...)
	corrupt[len(corrupt)-1] ^= 1
	p = admissionTestAcquire(t, a, admissionTestPrincipal("issuer", "gzip-checksum", Human))
	if _, err := p.CopyObject(context.Background(), io.Discard, bytes.NewReader(corrupt), AdmissionObject{model.BlobKind, uint64(len(frame) - 22), uint64(len(corrupt)), AdmissionGZIP, true}); !errors.Is(err, gzip.ErrChecksum) {
		t.Fatalf("invalid compressed checksum was accepted: %v", err)
	}
	truncated := compressed[:len(compressed)-1]
	p = admissionTestAcquire(t, a, admissionTestPrincipal("issuer", "gzip-truncated", Human))
	if _, err := p.CopyObject(context.Background(), io.Discard, bytes.NewReader(truncated), AdmissionObject{model.BlobKind, uint64(len(frame) - 22), uint64(len(truncated)), AdmissionGZIP, true}); err == nil {
		t.Fatal("truncated compressed frame was accepted")
	}

	for _, tc := range []struct {
		name  string
		input []byte
	}{
		{"trailing", append(append([]byte(nil), compressed...), 0x01)},
		{"second_member", append(append([]byte(nil), compressed...), admissionTestGZIP(t, frame)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &admissionCountReader{reader: bytes.NewReader(tc.input)}
			var dst bytes.Buffer
			p := admissionTestAcquire(t, a, admissionTestPrincipal("issuer", tc.name, Human))
			if _, err := p.CopyObject(context.Background(), &dst, r, AdmissionObject{model.BlobKind, uint64(len(frame) - 22), uint64(len(tc.input)), AdmissionGZIP, true}); !errors.Is(err, ErrAdmissionInvalid) {
				t.Fatalf("accepted trailing compressed data: %v", err)
			}
			if a.Stats().Active != 0 {
				t.Fatal("invalid compressed framing retained its permit")
			}
		})
	}
}

func TestAdmissionStreamingCancellationAndFailureRelease(t *testing.T) {
	a := admissionTestNew(t, nil)
	frame := admissionTestFrame([]byte("streaming"))
	principal := admissionTestPrincipal("issuer", "stream", Human)
	preCtx, preCancel := context.WithCancel(context.Background())
	preCancel()
	preReader := &admissionCountReader{reader: bytes.NewReader(frame)}
	var preOut bytes.Buffer
	p := admissionTestAcquire(t, a, principal)
	if _, err := p.CopyObject(preCtx, &preOut, preReader, AdmissionObject{model.BlobKind, 9, uint64(len(frame)), AdmissionRaw, true}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled copy: %v", err)
	}
	if preReader.calls != 0 || preOut.Len() != 0 || a.Stats().Active != 0 {
		t.Fatal("pre-canceled operation performed I/O or retained its permit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &admissionCancelReader{cancel: cancel, data: frame[:8]}
	var out bytes.Buffer
	p = admissionTestAcquire(t, a, principal)
	if _, err := p.CopyObject(ctx, &out, r, AdmissionObject{model.BlobKind, 9, uint64(len(frame)), AdmissionRaw, true}); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-stream cancellation: %v", err)
	}
	if out.Len() != 0 || a.Stats().Active != 0 {
		t.Fatal("canceled stream wrote more data or retained its permit")
	}

	readErr := errors.New("reader failure")
	p = admissionTestAcquire(t, a, principal)
	if _, err := p.CopyObject(context.Background(), io.Discard, admissionFailReader{readErr}, AdmissionObject{model.BlobKind, 9, uint64(len(frame)), AdmissionRaw, true}); !errors.Is(err, readErr) {
		t.Fatalf("source error lost: %v", err)
	}
	writeErr := errors.New("writer failure")
	p = admissionTestAcquire(t, a, principal)
	if _, err := p.CopyObject(context.Background(), admissionFailWriter{writeErr}, bytes.NewReader(frame), AdmissionObject{model.BlobKind, 9, uint64(len(frame)), AdmissionRaw, true}); !errors.Is(err, writeErr) {
		t.Fatalf("destination error lost: %v", err)
	}
	p = admissionTestAcquire(t, a, principal)
	if _, err := p.CopyObject(context.Background(), io.Discard, admissionFailReader{nil}, AdmissionObject{model.BlobKind, 9, uint64(len(frame)), AdmissionRaw, true}); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("no-progress reader did not stop: %v", err)
	}
	if got := a.Stats(); got.Active != 0 || got.Principals != 0 {
		t.Fatalf("stream errors leaked admission state: %+v", got)
	}

	blocked := admissionTestNew(t, func(l *AdmissionLimits) { l.InFlight, l.PerPrincipal, l.Waiters, l.PerPrincipalWaiters = 1, 1, 0, 0 })
	permit := admissionTestAcquire(t, blocked, principal)
	resume := make(chan struct{})
	writer := &admissionBlockingWriter{entered: make(chan struct{}), resume: resume}
	finished := make(chan error, 1)
	go func() {
		_, err := permit.CopyObject(context.Background(), writer, bytes.NewReader(frame), AdmissionObject{model.BlobKind, 9, uint64(len(frame)), AdmissionRaw, true})
		finished <- err
	}()
	select {
	case <-writer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not reach blocked destination")
	}
	permit.Release()
	if blocked.Stats().Active != 1 {
		t.Fatal("release removed a running stream slot before I/O returned")
	}
	if _, err := blocked.Acquire(context.Background(), principal); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("running stream slot admitted another request: %v", err)
	}
	close(resume)
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("blocked stream failed after resume: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked stream did not finish")
	}
	if got := blocked.Stats(); got.Active != 0 || got.Principals != 0 {
		t.Fatalf("running release leaked slot: %+v", got)
	}
}

func TestAdmissionReservationFailureIsAtomic(t *testing.T) {
	a := admissionTestNew(t, func(l *AdmissionLimits) {
		l.Bounds[AdmissionStreamBytes] = 8
		l.Bounds[AdmissionMetadataBytes] = 4
	})
	p := admissionTestAcquire(t, a, admissionTestPrincipal("issuer", "reserve", Human))
	if err := p.Reserve(AdmissionCost{AdmissionStreamBytes: 8, AdmissionMetadataBytes: 5}); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("oversized vector reservation: %v", err)
	}
	if err := p.Reserve(AdmissionCost{AdmissionStreamBytes: 8}); err != nil {
		t.Fatalf("failed vector reservation charged an earlier dimension: %v", err)
	}
	if err := p.Reserve(AdmissionCost{AdmissionMetadataBytes: 5}); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("reservation exceeded bounded metadata: %v", err)
	}
	clone := *p
	var releases sync.WaitGroup
	for i := 0; i < 16; i++ {
		releases.Add(1)
		go func(i int) {
			defer releases.Done()
			if i%2 == 0 {
				p.Release()
			} else {
				clone.Release()
			}
		}(i)
	}
	releases.Wait()
	if got := a.Stats(); got.Active != 0 || got.Principals != 0 {
		t.Fatalf("copied/repeated release was not exactly once: %+v", got)
	}
	if err := p.Reserve(AdmissionCost{}); !errors.Is(err, ErrAdmissionReleased) {
		t.Fatalf("released permit accepted reservation: %v", err)
	}
}

func TestAdmissionObjectAndRangeReservations(t *testing.T) {
	a := admissionTestNew(t, nil)
	p := admissionTestAcquire(t, a, admissionTestPrincipal("issuer", "read", Human))
	if err := p.ReserveReadObject(68<<20, 4<<20); err != nil {
		t.Fatalf("maximum whole-object stream reservation: %v", err)
	}
	if err := p.ReserveReadStream(); err != nil {
		t.Fatalf("idempotent terminal reserve: %v", err)
	}
	if err := p.ReserveReadObject(68<<20, 4<<20); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("stream budget admitted a second maximum object: %v", err)
	}
	if err := p.ReserveReadObject(1, 4<<20); err != nil {
		t.Fatalf("failed object reservation was not atomic: %v", err)
	}
	p.Release()

	p = admissionTestAcquire(t, a, admissionTestPrincipal("issuer", "range", Human))
	if err := p.ReserveRange(3, 4<<20); err != nil {
		t.Fatalf("conservative three-chunk range fits response cap: %v", err)
	}
	p.Release()
	p = admissionTestAcquire(t, a, admissionTestPrincipal("issuer", "range4", Human))
	if err := p.ReserveRange(4, 4<<20); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("four 4 MiB chunks exceeded unary response budget without rejection: %v", err)
	}
	p.Release()

	upload := admissionTestNew(t, func(l *AdmissionLimits) { l.Bounds[AdmissionChunkAttempts] = 2 })
	p = admissionTestAcquire(t, upload, admissionTestPrincipal("issuer", "upload", Human))
	if err := p.ReserveUploadChunk(22, 1); err != nil {
		t.Fatal(err)
	}
	if err := p.ReserveUploadChunk(22, 88); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("upload ingress beyond four declared frames: %v", err)
	}
	if err := p.ReserveUploadChunk(22, 1); err != nil {
		t.Fatalf("failed ingress attempt consumed attempt budget: %v", err)
	}
	if err := p.ReserveUploadChunk(22, 1); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("upload attempt budget exceeded: %v", err)
	}
	if err := p.ReserveUploadChunk(23, 1); !errors.Is(err, ErrAdmissionInvalid) {
		t.Fatalf("changed immutable upload frame: %v", err)
	}
	p.Release()
	p = admissionTestAcquire(t, a, admissionTestPrincipal("issuer", "large-upload", Human))
	maxFrame := uint64(1<<40) + 22
	if err := p.ReserveUploadChunk(maxFrame, 1); err != nil {
		t.Fatalf("maximum declared upload frame: %v", err)
	}
	if err := p.ReserveUploadChunk(maxFrame+1, 1); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("upload frame above canonical maximum: %v", err)
	}
	p.Release()
}

func TestAdmissionWaiterQueueBoundsAndCleanup(t *testing.T) {
	a := admissionTestNew(t, func(l *AdmissionLimits) {
		l.InFlight, l.PerPrincipal, l.Waiters, l.PerPrincipalWaiters = 1, 1, 2, 1
	})
	p1 := admissionTestPrincipal("issuer", "one", Human)
	p2 := admissionTestPrincipal("issuer", "two", BuildJob)
	owner := admissionTestAcquire(t, a, p1)
	cancel1, stop1 := context.WithCancel(context.Background())
	defer stop1()
	waiter1 := admissionStartWaiter(a, cancel1, p1)
	admissionWaitQueued(t, a, 1)
	if _, err := a.Acquire(context.Background(), p1); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("per-principal waiter bound not enforced: %v", err)
	}
	cancel2, stop2 := context.WithCancel(context.Background())
	defer stop2()
	waiter2 := admissionStartWaiter(a, cancel2, p2)
	admissionWaitQueued(t, a, 2)
	if _, err := a.Acquire(context.Background(), admissionTestPrincipal("issuer", "third", Human)); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("global waiter bound not enforced: %v", err)
	}
	for i := 0; i < 32; i++ {
		attacker := admissionTestPrincipal("untrusted", string(rune('a'+i)), Human)
		if _, err := a.Acquire(context.Background(), attacker); !errors.Is(err, ErrAdmissionLimit) {
			t.Fatalf("attacker %d bypassed full queue: %v", i, err)
		}
	}
	if got := a.Stats(); got.Active != 1 || got.Queued != 2 || got.Principals != 1 {
		t.Fatalf("rejected callers grew retained state: %+v", got)
	}
	stop1()
	select {
	case result := <-waiter1:
		if !errors.Is(result.err, context.Canceled) || result.permit != nil {
			t.Fatalf("canceled waiter result: %+v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled waiter did not leave queue")
	}
	admissionWaitQueued(t, a, 1)
	owner.Release()
	select {
	case result := <-waiter2:
		if result.err != nil || result.permit == nil {
			t.Fatalf("remaining waiter not admitted after release: %+v", result)
		}
		result.permit.Release()
	case <-time.After(2 * time.Second):
		t.Fatal("queued principal was not admitted")
	}
	if got := a.Stats(); got.Active != 0 || got.Queued != 0 || got.Principals != 0 {
		t.Fatalf("waiter cancellation/release leaked state: %+v", got)
	}

	for i := 0; i < 24; i++ {
		race := admissionTestNew(t, func(l *AdmissionLimits) {
			l.InFlight, l.PerPrincipal, l.Waiters, l.PerPrincipalWaiters = 1, 1, 1, 1
		})
		principal := admissionTestPrincipal("issuer", "race", Human)
		owner := admissionTestAcquire(t, race, principal)
		ctx, cancel := context.WithCancel(context.Background())
		waiter := admissionStartWaiter(race, ctx, principal)
		admissionWaitQueued(t, race, 1)
		start := make(chan struct{})
		var pair sync.WaitGroup
		pair.Add(2)
		go func() { defer pair.Done(); <-start; cancel() }()
		go func() { defer pair.Done(); <-start; owner.Release() }()
		close(start)
		pair.Wait()
		select {
		case result := <-waiter:
			if result.err != nil && (!errors.Is(result.err, context.Canceled) || result.permit != nil) {
				t.Fatalf("cancel/grant race returned invalid failure: %+v", result)
			}
			if result.err == nil {
				if result.permit == nil {
					t.Fatal("cancel/grant race returned neither permit nor error")
				}
				result.permit.Release()
			}
		case <-time.After(2 * time.Second):
			t.Fatal("cancel/grant race left waiter blocked")
		}
		if got := race.Stats(); got.Active != 0 || got.Queued != 0 || got.Principals != 0 {
			t.Fatalf("cancel/grant race leaked state: %+v", got)
		}
	}
}

func TestAdmissionPrincipalTupleIsolation(t *testing.T) {
	a := admissionTestNew(t, func(l *AdmissionLimits) {
		l.InFlight, l.PerPrincipal, l.Waiters, l.PerPrincipalWaiters = 3, 1, 0, 0
	})
	principals := []PrincipalID{
		admissionTestPrincipal("a", "bc", Human),
		admissionTestPrincipal("ab", "c", Human),
		admissionTestPrincipal("a", "bc", BuildJob),
	}
	type tupleAcquireResult struct {
		index  int
		permit *AdmissionPermit
		err    error
	}
	start := make(chan struct{})
	ready := make(chan struct{}, len(principals))
	results := make(chan tupleAcquireResult, len(principals))
	for i, principal := range principals {
		go func(i int, principal PrincipalID) {
			ready <- struct{}{}
			<-start
			p, err := a.Acquire(context.Background(), principal)
			results <- tupleAcquireResult{i, p, err}
		}(i, principal)
	}
	for range principals {
		<-ready
	}
	close(start)
	permits := make([]*AdmissionPermit, len(principals))
	for range principals {
		result := <-results
		if result.err != nil || result.permit == nil {
			t.Fatalf("distinct tuple blocked by another principal: %+v", result)
		}
		permits[result.index] = result.permit
	}
	if got := a.Stats(); got.Active != 3 || got.Principals != 3 {
		t.Fatalf("principal tuple keys collapsed: %+v", got)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Acquire(canceled, principals[0]); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled acquire: %v", err)
	}
	invalid := []PrincipalID{
		{}, admissionTestPrincipal(string(bytes.Repeat([]byte{'i'}, 4097)), "subject", Human),
		admissionTestPrincipal("issuer", "subject", "unknown"),
	}
	for _, principal := range invalid {
		if _, err := a.Acquire(context.Background(), principal); !errors.Is(err, ErrAdmissionInvalid) {
			t.Fatalf("invalid identity entered admission: %v", err)
		}
	}
	if got := a.Stats(); got.Active != 3 || got.Principals != 3 || got.Queued != 0 {
		t.Fatalf("invalid identities or canceled acquire retained state: %+v", got)
	}
	if _, err := a.Acquire(context.Background(), principals[0]); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("per-principal cap not enforced for identical tuple: %v", err)
	}
	permits[1].Release()
	reacquired := admissionTestAcquire(t, a, principals[1])
	if got := a.Stats(); got.Active != 3 || got.Principals != 3 {
		t.Fatalf("released tuple could not reacquire independently: %+v", got)
	}
	for _, p := range permits {
		p.Release()
	}
	reacquired.Release()
	if got := a.Stats(); got.Active != 0 || got.Principals != 0 {
		t.Fatalf("principal entries remained after release: %+v", got)
	}
}

func TestAdmissionPrincipalAggregateCaps(t *testing.T) {
	defaultAdmission := admissionTestNew(t, nil)
	principal := admissionTestPrincipal("issuer", "bounded", Human)
	held := make([]*AdmissionPermit, 0, 8)
	for i := 0; i < 8; i++ {
		held = append(held, admissionTestAcquire(t, defaultAdmission, principal))
	}
	if _, err := defaultAdmission.Acquire(context.Background(), principal); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("ninth active-or-queued call admitted for one principal: %v", err)
	}
	if got := defaultAdmission.Stats(); got.Active != 8 || got.Queued != 0 || got.Principals != 1 {
		t.Fatalf("same-principal call cap grew queue or principal state: %+v", got)
	}
	for _, p := range held {
		p.Release()
	}

	a := admissionTestNew(t, func(l *AdmissionLimits) {
		l.Bounds[AdmissionStagingBytes] = 8
		l.Bounds[AdmissionRetainedSessions] = 8
	})
	p1 := admissionTestAcquire(t, a, principal)
	p2 := admissionTestAcquire(t, a, principal)
	if err := p1.Reserve(AdmissionCost{AdmissionStagingBytes: 8, AdmissionRetainedSessions: 8}); err != nil {
		t.Fatal(err)
	}
	if err := p2.Reserve(AdmissionCost{AdmissionStagingBytes: 1}); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("per-principal staging aggregate exceeded: %v", err)
	}
	if err := p2.Reserve(AdmissionCost{AdmissionRetainedSessions: 1}); !errors.Is(err, ErrAdmissionLimit) {
		t.Fatalf("per-principal session aggregate exceeded: %v", err)
	}
	p1.Release()
	if err := p2.Reserve(AdmissionCost{AdmissionStagingBytes: 8, AdmissionRetainedSessions: 8}); err != nil {
		t.Fatalf("released reservation did not return principal capacity: %v", err)
	}
	other := admissionTestAcquire(t, a, admissionTestPrincipal("issuer", "other", Human))
	if err := other.Reserve(AdmissionCost{AdmissionStagingBytes: 8, AdmissionRetainedSessions: 8}); err != nil {
		t.Fatalf("one principal consumed another principal's quota: %v", err)
	}
	if len(a.reserved) != 2 {
		t.Fatalf("aggregate reservation map does not match active principals: %d", len(a.reserved))
	}
	p2.Release()
	other.Release()
	if len(a.reserved) != 0 || a.Stats().Active != 0 {
		t.Fatalf("aggregate reservations survived final release: %+v", a.Stats())
	}
}
