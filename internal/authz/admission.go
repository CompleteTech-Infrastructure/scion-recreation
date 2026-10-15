package authz

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"sync"

	"canopy.local/canopy/internal/model"
)

var (
	ErrAdmissionInvalid  = errors.New("invalid admission input")
	ErrAdmissionLimit    = errors.New("admission resource exhausted")
	ErrAdmissionReleased = errors.New("admission permit released")
)

// AdmissionResource identifies independent objects-v1/grants-v1 ceilings. Check
// scalar lengths/depths before decoding; Reserve cumulative costs before work.
type AdmissionResource uint8

const (
	AdmissionReadRequestBytes AdmissionResource = iota
	AdmissionUploadRequestBytes
	AdmissionResponseBytes
	AdmissionDepth
	AdmissionWholeFrameBytes
	AdmissionWholeEncodedBytes
	AdmissionStreamBytes
	AdmissionChunkBytes
	AdmissionWantedObjects
	AdmissionStreamFrames
	AdmissionMetadataBytes
	AdmissionGrantBytes
	AdmissionGrantTokenBytes
	AdmissionResumeTokenBytes
	AdmissionAudienceBytes
	AdmissionKeyIDBytes
	AdmissionRangeChunks
	AdmissionProofBytes
	AdmissionProofSiblings
	AdmissionRetries
	AdmissionDeadlineMillis
	AdmissionExpansionRatio
	AdmissionDecoderWindowBytes
	AdmissionSessionMillis
	AdmissionResolvedProofBytes
	AdmissionIntervals
	AdmissionStateBytes
	AdmissionCompletionRecords
	AdmissionRetainedSessions
	AdmissionLogicalBytes
	AdmissionWork
	AdmissionPolicyRules
	AdmissionVisits
	AdmissionTraversalDepth
	AdmissionStagingBytes
	AdmissionChunkAttempts
	AdmissionDistinctChunks
	AdmissionInputBytes
	AdmissionDecodedBytes
	AdmissionEnvelopeBytes
	AdmissionUploadIngressBytes
	AdmissionParents
	AdmissionOperations
	AdmissionPathBytes
	AdmissionPathComponents
	AdmissionIdentityBytes
	AdmissionMessageBytes
	AdmissionEncodingBytes
	AdmissionResourceCount
)

type AdmissionCost [AdmissionResourceCount]uint64
type AdmissionLimits struct {
	InFlight, PerPrincipal, Waiters, PerPrincipalWaiters uint64
	Bounds                                               AdmissionCost
}

// Defaults are the accepted protocol maxima, not measured service capacity.
// Queues are additionally bounded globally; principal quotas aggregate sessions.
func DefaultAdmissionLimits() AdmissionLimits {
	return AdmissionLimits{8, 8, 64, 8, AdmissionCost{
		2097152, 8388608, 16777216, 16, 67108886, 71303168,
		134217728, 4194304, 128, 8192, 16384, 8192, 4096, 4096,
		256, 64, 64, 65536, 64, 3, 30000, 64, 8388608, 3600000,
		1048576, 64, 2097152, 128, 8, 1 << 40, 16777216, 65536,
		1048576, 4096, (1 << 40) + 22, 1048580, 262145,
		(1 << 40) + 22, (1 << 40) + 22, 1024, 4 * ((1 << 40) + 22),
		1024, 1000000, 65535, 1024, 65536, 16777216, 256,
	}}
}

type Admission struct {
	mu         sync.Mutex
	limits     AdmissionLimits
	active     uint64
	principals map[PrincipalID]uint64
	reserved   map[PrincipalID]AdmissionCost
	queue      []*admissionWaiter
}
type admissionWaiter struct {
	principal PrincipalID
	ready     chan struct{}
	permit    *AdmissionPermit
}
type admissionReservation struct {
	owner                 *Admission
	principal             PrincipalID
	used                  AdmissionCost
	held, closed, running bool
	readStarted           bool
	uploadFrame           uint64
}

// Copies share one reservation. Release is idempotent, including concurrent
// copies. A running CopyObject retains its slot until that operation returns.
type AdmissionPermit struct{ state *admissionReservation }
type AdmissionStats struct{ Active, Queued, Principals uint64 }

func NewAdmission(limits AdmissionLimits) (*Admission, error) {
	max := DefaultAdmissionLimits()
	if limits.InFlight == 0 || limits.InFlight > max.InFlight || limits.PerPrincipal == 0 || limits.PerPrincipal > limits.InFlight || limits.Waiters > max.Waiters || limits.PerPrincipalWaiters > max.PerPrincipalWaiters {
		return nil, ErrAdmissionInvalid
	}
	for i, v := range limits.Bounds {
		if v > max.Bounds[i] {
			return nil, ErrAdmissionInvalid
		}
	}
	return &Admission{limits: limits, principals: make(map[PrincipalID]uint64), reserved: make(map[PrincipalID]AdmissionCost)}, nil
}
func (a *Admission) Check(resource AdmissionResource, value uint64) error {
	if a == nil || resource >= AdmissionResourceCount {
		return ErrAdmissionInvalid
	}
	if value > a.limits.Bounds[resource] {
		return ErrAdmissionLimit
	}
	return nil
}

type AdmissionRequestKind uint8

const (
	AdmissionReadRequest AdmissionRequestKind = iota
	AdmissionBeginRequest
	AdmissionUploadRequest
	AdmissionResponse
)

// bytes excludes the exactly five transport framing bytes. Message compression
// is forbidden; actual streaming wire bytes must be checked as well as lengths.
func (a *Admission) CheckRequest(kind AdmissionRequestKind, bytes, depth uint64, compressed bool) error {
	resource := AdmissionReadRequestBytes
	switch kind {
	case AdmissionReadRequest, AdmissionBeginRequest:
	case AdmissionUploadRequest:
		resource = AdmissionUploadRequestBytes
	case AdmissionResponse:
		resource = AdmissionResponseBytes
	default:
		return ErrAdmissionInvalid
	}
	if compressed {
		return ErrAdmissionInvalid
	}
	if err := a.Check(AdmissionDepth, depth); err != nil {
		return err
	}
	return a.Check(resource, bytes)
}
func admissionPrincipalValid(p PrincipalID) bool {
	if !boundedIdentityClaim(p.Issuer) || !boundedIdentityClaim(p.Subject) {
		return false
	}
	switch p.Class {
	case Human, BuildJob, ModelWorker, ServiceAccount:
		return true
	}
	return false
}

// Acquire receives an already authenticated identity. It grants no repository
// rights. No goroutine is spawned; rejected callers create no retained state.
func (a *Admission) Acquire(ctx context.Context, principal PrincipalID) (*AdmissionPermit, error) {
	if a == nil || ctx == nil || !admissionPrincipalValid(principal) {
		return nil, ErrAdmissionInvalid
	}
	a.mu.Lock()
	if err := ctx.Err(); err != nil {
		a.mu.Unlock()
		return nil, err
	}
	var count uint64
	for _, w := range a.queue {
		if w.principal == principal {
			count++
		}
	}
	if a.principals[principal]+count >= 8 {
		a.mu.Unlock()
		return nil, ErrAdmissionLimit
	}
	if a.active < a.limits.InFlight && a.principals[principal] < a.limits.PerPrincipal {
		p := a.admissionGrant(principal)
		a.mu.Unlock()
		return p, nil
	}
	if uint64(len(a.queue)) >= a.limits.Waiters || count >= a.limits.PerPrincipalWaiters {
		a.mu.Unlock()
		return nil, ErrAdmissionLimit
	}
	w := &admissionWaiter{principal: principal, ready: make(chan struct{})}
	a.queue = append(a.queue, w)
	a.mu.Unlock()
	select {
	case <-w.ready:
	case <-ctx.Done():
	}
	a.mu.Lock()
	if err := ctx.Err(); err != nil {
		if w.permit != nil {
			a.admissionRelease(w.permit.state)
		} else {
			for i, v := range a.queue {
				if v == w {
					a.admissionRemove(i)
					break
				}
			}
		}
		a.mu.Unlock()
		return nil, err
	}
	p := w.permit
	a.mu.Unlock()
	return p, nil
}
func (a *Admission) admissionGrant(p PrincipalID) *AdmissionPermit {
	a.active++
	a.principals[p]++
	return &AdmissionPermit{&admissionReservation{owner: a, principal: p, held: true}}
}
func (a *Admission) admissionRemove(i int) {
	copy(a.queue[i:], a.queue[i+1:])
	a.queue[len(a.queue)-1] = nil
	a.queue = a.queue[:len(a.queue)-1]
}
func (a *Admission) admissionRelease(s *admissionReservation) {
	if !s.held {
		return
	}
	s.held = false
	s.closed = true
	shared := a.reserved[s.principal]
	shared[AdmissionStagingBytes] -= s.used[AdmissionStagingBytes]
	shared[AdmissionRetainedSessions] -= s.used[AdmissionRetainedSessions]
	if shared[AdmissionStagingBytes] == 0 && shared[AdmissionRetainedSessions] == 0 {
		delete(a.reserved, s.principal)
	} else {
		a.reserved[s.principal] = shared
	}
	a.active--
	a.principals[s.principal]--
	if a.principals[s.principal] == 0 {
		delete(a.principals, s.principal)
	}
	for i := 0; i < len(a.queue) && a.active < a.limits.InFlight; {
		w := a.queue[i]
		if a.principals[w.principal] >= a.limits.PerPrincipal {
			i++
			continue
		}
		w.permit = a.admissionGrant(w.principal)
		a.admissionRemove(i)
		close(w.ready)
	}
}
func (p *AdmissionPermit) Release() {
	if p == nil || p.state == nil {
		return
	}
	s := p.state
	a := s.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	s.closed = true
	if !s.running {
		a.admissionRelease(s)
	}
}
func (a *Admission) Stats() AdmissionStats {
	if a == nil {
		return AdmissionStats{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return AdmissionStats{a.active, uint64(len(a.queue)), uint64(len(a.principals))}
}

// Reserve is all-or-nothing, with checked subtraction before any addition. A
// failed reservation changes nothing. Costs are consumed, never refunded here.
func (p *AdmissionPermit) Reserve(cost AdmissionCost) error {
	if p == nil || p.state == nil {
		return ErrAdmissionReleased
	}
	s := p.state
	a := s.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.admissionReserve(s, cost)
}
func (a *Admission) admissionReserve(s *admissionReservation, cost AdmissionCost) error {
	if s.closed {
		return ErrAdmissionReleased
	}
	for i, n := range cost {
		if n > a.limits.Bounds[i]-s.used[i] {
			return ErrAdmissionLimit
		}
	}
	shared := a.reserved[s.principal]
	for _, i := range [...]AdmissionResource{AdmissionStagingBytes, AdmissionRetainedSessions} {
		if cost[i] > a.limits.Bounds[i]-shared[i] {
			return ErrAdmissionLimit
		}
	}
	for i, n := range cost {
		s.used[i] += n
	}
	if cost[AdmissionStagingBytes] != 0 || cost[AdmissionRetainedSessions] != 0 {
		shared[AdmissionStagingBytes] += cost[AdmissionStagingBytes]
		shared[AdmissionRetainedSessions] += cost[AdmissionRetainedSessions]
		a.reserved[s.principal] = shared
	}
	return nil
}

// ReserveReadStream preserves mandatory terminals/final even when no object fits.
func (p *AdmissionPermit) ReserveReadStream() error {
	if p == nil || p.state == nil {
		return ErrAdmissionReleased
	}
	s := p.state
	a := s.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.closed {
		return ErrAdmissionReleased
	}
	if s.readStarted {
		return nil
	}
	if err := a.admissionReserve(s, AdmissionCost{AdmissionStreamBytes: 2162688, AdmissionStreamFrames: 129}); err != nil {
		return err
	}
	s.readStarted = true
	return nil
}
func (p *AdmissionPermit) ReserveReadObject(encoded, chunk uint64) error {
	if p == nil || p.state == nil {
		return ErrAdmissionReleased
	}
	a := p.state.owner
	if chunk == 0 || encoded == 0 {
		return ErrAdmissionInvalid
	}
	if err := a.Check(AdmissionChunkBytes, chunk); err != nil {
		return err
	}
	if err := a.Check(AdmissionWholeEncodedBytes, encoded); err != nil {
		return err
	}
	frames := encoded / chunk
	if encoded%chunk != 0 {
		frames++
	}
	frames++ // start
	// encoded is already bounded; division checks precede multiplication.
	limit := a.limits.Bounds[AdmissionStreamBytes]
	if encoded > limit || frames > (limit-encoded)/16384 {
		return ErrAdmissionLimit
	}
	s := p.state
	a.mu.Lock()
	defer a.mu.Unlock()
	cost := AdmissionCost{AdmissionStreamBytes: encoded + frames*16384, AdmissionStreamFrames: frames, AdmissionWantedObjects: 1}
	if !s.readStarted {
		if cost[AdmissionStreamBytes] > limit || 2162688 > limit-cost[AdmissionStreamBytes] {
			return ErrAdmissionLimit
		}
		cost[AdmissionStreamBytes] += 2162688
		cost[AdmissionStreamFrames] += 129
	}
	if err := a.admissionReserve(s, cost); err != nil {
		return err
	}
	s.readStarted = true
	return nil
}
func (p *AdmissionPermit) ReserveRange(chunks, chunk uint64) error {
	if p == nil || p.state == nil {
		return ErrAdmissionReleased
	}
	a := p.state.owner
	if chunk == 0 {
		return ErrAdmissionInvalid
	}
	if err := a.Check(AdmissionRangeChunks, chunks); err != nil {
		return err
	}
	if err := a.Check(AdmissionChunkBytes, chunk); err != nil {
		return err
	}
	limit := a.limits.Bounds[AdmissionResponseBytes]
	if limit < 16384 || chunks > (limit-16384)/(chunk+65536+64) {
		return ErrAdmissionLimit
	}
	return p.Reserve(AdmissionCost{AdmissionResponseBytes: 16384 + chunks*(chunk+65536+64)})
}

// Retain this permit's counters across upload chunk attempts, including retries.
// The frame binding is immutable; failed attempts never reset ingress credit.
// A service must retain/expire this ledger with its authenticated upload state.
func (p *AdmissionPermit) ReserveUploadChunk(frame, bytes uint64) error {
	if p == nil || p.state == nil {
		return ErrAdmissionReleased
	}
	s := p.state
	a := s.owner
	if frame < 22 || frame > (1<<40)+22 {
		return ErrAdmissionLimit
	}
	if bytes == 0 {
		return ErrAdmissionInvalid
	}
	if err := a.Check(AdmissionChunkBytes, bytes); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.uploadFrame != 0 && s.uploadFrame != frame {
		return ErrAdmissionInvalid
	}
	if s.used[AdmissionUploadIngressBytes] > 4*frame || bytes > 4*frame-s.used[AdmissionUploadIngressBytes] {
		return ErrAdmissionLimit
	}
	if err := a.admissionReserve(s, AdmissionCost{AdmissionUploadIngressBytes: bytes, AdmissionChunkAttempts: 1}); err != nil {
		return err
	}
	s.uploadFrame = frame
	return nil
}

type AdmissionCompression uint8

const (
	AdmissionRaw AdmissionCompression = iota
	AdmissionGZIP
)

type AdmissionObject struct {
	Kind                     model.ObjectKind
	PayloadBytes, InputBytes uint64
	Compression              AdmissionCompression
	Whole                    bool // false selects RAW upload, preserving the full 2^40 blob format
}

func (a *Admission) admissionObject(spec AdmissionObject) (uint64, error) {
	if err := model.ValidatePayloadLength(spec.Kind, spec.PayloadBytes); err != nil {
		return 0, ErrAdmissionLimit
	}
	frame := spec.PayloadBytes + 22 // format bound proved this addition safe
	if err := a.Check(AdmissionDecodedBytes, frame); err != nil {
		return 0, err
	}
	if err := a.Check(AdmissionInputBytes, spec.InputBytes); err != nil {
		return 0, err
	}
	if spec.Whole {
		if err := a.Check(AdmissionWholeFrameBytes, frame); err != nil {
			return 0, err
		}
		if err := a.Check(AdmissionWholeEncodedBytes, spec.InputBytes); err != nil {
			return 0, err
		}
	}
	switch spec.Compression {
	case AdmissionRaw:
		if frame != spec.InputBytes {
			return 0, ErrAdmissionInvalid
		}
	case AdmissionGZIP:
		ratio := a.limits.Bounds[AdmissionExpansionRatio]
		if !spec.Whole || ratio == 0 || a.limits.Bounds[AdmissionDecoderWindowBytes] < 32768 {
			return 0, ErrAdmissionInvalid
		}
		minimum := frame / ratio
		if frame%ratio != 0 {
			minimum++
		}
		if spec.InputBytes < minimum {
			return 0, ErrAdmissionLimit
		}
	default:
		return 0, ErrAdmissionInvalid
	}
	return frame, nil
}

// CopyObject copies exactly one declared canonical frame to UNVERIFIED staging;
// it does not parse/hash the frame or authorize delivery. It always releases its
// permit. RAW uploads and single-member GZIP whole objects use fixed buffers.
// Cancellation is checked at each I/O boundary; caller-owned readers/writers
// must themselves support cancellation of blocking I/O. No escape goroutine is
// created. Staging must be discarded on error and verified before publication.
func (p *AdmissionPermit) CopyObject(ctx context.Context, dst io.Writer, src io.Reader, spec AdmissionObject) (written uint64, err error) {
	if err = p.admissionStart(); err != nil {
		return 0, err
	}
	defer p.admissionFinish()
	a := p.state.owner
	if ctx == nil || dst == nil || src == nil {
		return 0, ErrAdmissionInvalid
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	frame, err := a.admissionObject(spec)
	if err != nil {
		return 0, err
	}
	if err = p.Reserve(AdmissionCost{AdmissionInputBytes: spec.InputBytes, AdmissionDecodedBytes: frame, AdmissionLogicalBytes: spec.PayloadBytes}); err != nil {
		return 0, err
	}
	if !spec.Whole {
		if err = p.Reserve(AdmissionCost{AdmissionStagingBytes: frame}); err != nil {
			return 0, err
		}
	}
	in := &admissionInput{ctx: ctx, src: src, remaining: spec.InputBytes}
	var decoded io.Reader = in
	if spec.Compression == AdmissionGZIP {
		g, e := gzip.NewReader(in)
		if e != nil {
			return 0, e
		}
		defer g.Close()
		g.Multistream(false)
		decoded = g
	}
	written, err = admissionCopy(ctx, dst, decoded, frame)
	if err != nil {
		return written, err
	}
	// ByteReader prevents gzip read-ahead from hiding trailing data/members.
	if in.remaining != 0 {
		return written, ErrAdmissionInvalid
	}
	var extra [1]byte
	if _, err = in.Read(extra[:]); err != io.EOF {
		if err == nil {
			err = ErrAdmissionInvalid
		}
		return written, err
	}
	return written, nil
}

// CopyRequest checks declared AND actual uncompressed message bytes before any
// decoder work. Depth/field checks on original wire remain the decoder's duty.
func (p *AdmissionPermit) CopyRequest(ctx context.Context, dst io.Writer, src io.Reader, kind AdmissionRequestKind, bytes, depth uint64, compressed bool) (uint64, error) {
	if err := p.admissionStart(); err != nil {
		return 0, err
	}
	defer p.admissionFinish()
	if ctx == nil || dst == nil || src == nil {
		return 0, ErrAdmissionInvalid
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := p.state.owner.CheckRequest(kind, bytes, depth, compressed); err != nil {
		return 0, err
	}
	if err := p.Reserve(AdmissionCost{AdmissionInputBytes: bytes}); err != nil {
		return 0, err
	}
	return admissionCopy(ctx, dst, &admissionInput{ctx: ctx, src: src, remaining: bytes}, bytes)
}
func (p *AdmissionPermit) admissionStart() error {
	if p == nil || p.state == nil {
		return ErrAdmissionReleased
	}
	s := p.state
	a := s.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.closed || s.running {
		return ErrAdmissionReleased
	}
	s.running = true
	return nil
}
func (p *AdmissionPermit) admissionFinish() {
	s := p.state
	a := s.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	s.running = false
	a.admissionRelease(s)
}
func admissionCopy(ctx context.Context, dst io.Writer, decoded io.Reader, frame uint64) (written uint64, err error) {
	var buffer [32768]byte
	for {
		if err = ctx.Err(); err != nil {
			return written, err
		}
		remaining := frame - written
		size := uint64(len(buffer))
		if remaining < size {
			size = remaining + 1
		}
		n, e := decoded.Read(buffer[:int(size)])
		if n < 0 || n > int(size) {
			return written, ErrAdmissionInvalid
		}
		if uint64(n) > remaining {
			return written, ErrAdmissionLimit
		}
		if n > 0 {
			if err = ctx.Err(); err != nil {
				return written, err
			}
			m, we := dst.Write(buffer[:n])
			if m < 0 || m > n {
				return written, ErrAdmissionInvalid
			}
			written += uint64(m)
			if we != nil {
				return written, we
			}
			if m != n {
				return written, io.ErrShortWrite
			}
		}
		if e != nil {
			if e != io.EOF {
				return written, e
			}
			break
		}
		if n == 0 {
			return written, io.ErrNoProgress
		}
	}
	if written != frame {
		return written, io.ErrUnexpectedEOF
	}
	return written, nil
}

type admissionInput struct {
	ctx       context.Context
	src       io.Reader
	remaining uint64
}

func (r *admissionInput) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		var extra [1]byte
		n, err := r.src.Read(extra[:])
		if n != 0 {
			return 0, ErrAdmissionLimit
		}
		if err == nil {
			return 0, io.ErrNoProgress
		}
		return 0, err
	}
	if uint64(len(b)) > r.remaining {
		b = b[:int(r.remaining)]
	}
	n, err := r.src.Read(b)
	if n < 0 || n > len(b) {
		return 0, ErrAdmissionInvalid
	}
	r.remaining -= uint64(n)
	if n == 0 && err == nil {
		return 0, io.ErrNoProgress
	}
	return n, err
}
func (r *admissionInput) ReadByte() (byte, error) {
	var b [1]byte
	n, err := r.Read(b[:])
	if n == 1 {
		return b[0], nil
	}
	return 0, err
}
