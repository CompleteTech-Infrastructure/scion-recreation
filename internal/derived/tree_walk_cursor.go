package derived

import (
	"context"
	"errors"
	"math"
	"reflect"
	"sync/atomic"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/metadata"
)

// TreeCandidateReader is trusted service composition, never request input.
// GetCandidate must honor cancellation, read at most MaxTreePageBytes+1 bytes,
// authorize every lookup/delivery, and return owned immutable bytes. The private
// treepages.Staging store implements this interface. A digest is not a grant.
type TreeCandidateReader interface {
	GetCandidate(context.Context, TreePageID) ([]byte, error)
}

// TreeWalkLimits admits cumulative work for one in-process attempt. Fetches
// includes ancestor re-reads; Terminals includes directory entries and every
// repeated context. PageBytes counts all returned frame bytes, including errors.
// MaxDepth bounds lazy DFS frames (not path components), 1..65536. No zero means
// unlimited. PageBytes must leave one maximum-frame reservation for each read;
// unused reservation is refunded after that read. This can conservatively stop
// before a small frame which would have fit if its size were already known.
type TreeWalkLimits struct {
	Fetches, Terminals, PageBytes uint64
	MaxDepth                      int
}

// TreeWalkQuantum is additionally capped by the TREE-v1 work-quantum limits.
// Parents are re-read rather than retaining a page buffer per ancestor.
type TreeWalkQuantum struct{ Fetches, Terminals, PageBytes uint64 }
type TreeWalkUsage struct{ Fetches, Terminals, PageBytes uint64 }

// TreeWalkProgress is private topology progress, NOT a durable complete tree,
// retention/blob receipt, publication, checkpoint or authorized projection.
// Usage remains available on failure; TopologyDone is always false on error.
type TreeWalkProgress struct {
	Quantum, Total TreeWalkUsage
	TopologyDone   bool
}

var ErrTreeWalkBusy = errors.New("tree topology cursor busy")

type treeWalkFrame struct {
	id                                TreePageID
	base, dirEnd, componentStart, end int
	next                              int // directory target first (if present), then radix children
	entered                           bool
}

// TreeWalkCursor checks a stored page topology across bounded calls. It owns
// only one 65535-byte path, a bounded lazy stack and an active-ancestor ID set;
// it retains no frame cache, leaf list or repository mirror. Do not copy it.
// Any provider/validation/cancellation/job-limit failure permanently poisons
// this attempt. A caller cannot reset cumulative work by resuming after error.
// Process loss discards the attempt: durable continuation/fencing is separate.
type TreeWalkCursor struct {
	busy    atomic.Bool
	reader  TreeCandidateReader
	limits  TreeWalkLimits
	used    TreeWalkUsage
	stack   []treeWalkFrame
	active  map[TreePageID]bool
	path    []byte
	failure error
}

func NewTreeWalkCursor(root TreePageID, reader TreeCandidateReader, limits TreeWalkLimits) (*TreeWalkCursor, error) {
	nilReader := reader == nil
	if !nilReader {
		v := reflect.ValueOf(reader)
		switch v.Kind() {
		case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
			nilReader = v.IsNil()
		}
	}
	if root.Validate() != nil || nilReader || limits.Fetches == 0 || limits.Fetches > math.MaxInt64 || limits.Terminals == 0 || limits.Terminals > math.MaxInt64 || limits.PageBytes < MaxTreePageBytes || limits.PageBytes > math.MaxInt64 || limits.MaxDepth < 1 || limits.MaxDepth > 65536 {
		return nil, metadata.ErrInvalidArgument
	}
	c := &TreeWalkCursor{reader: reader, limits: limits,
		stack: make([]treeWalkFrame, 1, limits.MaxDepth),
		path:  make([]byte, 0, int(model.MaxPathBytes)), active: make(map[TreePageID]bool)}
	c.stack[0].id = root
	return c, nil
}

func validTreeQuantum(q TreeWalkQuantum) bool {
	return q.Fetches > 0 && q.Fetches <= 4096 && q.Terminals > 0 && q.Terminals <= 4096 && q.PageBytes >= MaxTreePageBytes && q.PageBytes <= 4096*MaxTreePageBytes
}

// Advance returns pending with nil error when only this quantum is exhausted.
// Every fetch is pre-admitted for its worst-case bytes/entry, then verified in
// its exact current context. Repeated shared-page occurrences are never skipped.
// Completion rechecks cancellation, including calls after an earlier completion.
// Admission/reader errors provide no root or success. Concurrent calls fail
// immediately; no unbounded wait queue or global/repository lock is introduced.
func (c *TreeWalkCursor) Advance(ctx context.Context, q TreeWalkQuantum) (p TreeWalkProgress, err error) {
	if c == nil || c.reader == nil || c.limits.MaxDepth == 0 || ctx == nil || !validTreeQuantum(q) {
		return p, metadata.ErrInvalidArgument
	}
	if !c.busy.CompareAndSwap(false, true) {
		return p, ErrTreeWalkBusy
	}
	defer c.busy.Store(false)
	p.Total = c.used
	if c.failure != nil {
		return p, c.failure
	}
	fail := func(e error) (TreeWalkProgress, error) { c.failure = e; p.Total = c.used; return p, e }
	for {
		if e := ctx.Err(); e != nil {
			return fail(e)
		}
		if len(c.stack) == 0 {
			p.Total = c.used
			p.TopologyDone = true
			return p, nil
		}
		f := &c.stack[len(c.stack)-1]
		entry := uint64(0)
		if !f.entered {
			entry = 1
		}
		if c.used.Fetches == c.limits.Fetches || MaxTreePageBytes > c.limits.PageBytes-c.used.PageBytes || entry > c.limits.Terminals-c.used.Terminals {
			return fail(metadata.ErrResourceExhausted)
		}
		if p.Quantum.Fetches == q.Fetches || MaxTreePageBytes > q.PageBytes-p.Quantum.PageBytes || entry > q.Terminals-p.Quantum.Terminals {
			p.Total = c.used
			return p, nil
		}
		c.used.Fetches++
		p.Quantum.Fetches++
		frame, e := c.reader.GetCandidate(ctx, f.id)
		n := uint64(len(frame))
		// Oversized returns violate the trusted provider contract. Charge the
		// reserved maximum and poison the attempt; never hash/decode the excess.
		charge := min(n, uint64(MaxTreePageBytes))
		c.used.PageBytes += charge
		p.Quantum.PageBytes += charge
		if n > MaxTreePageBytes {
			return fail(errors.Join(ErrTreePage, e))
		}
		if e != nil {
			return fail(e)
		}
		if e = ctx.Err(); e != nil {
			return fail(e)
		}
		page, e := DecodeTreePageAt(frame, f.id, c.path[:f.dirEnd], c.path[f.componentStart:f.base])
		if e != nil {
			return fail(e)
		}
		if !f.entered {
			if page.Tag != 0 {
				c.used.Terminals++
				p.Quantum.Terminals++
			}
			if len(c.path)+len(page.Label) > cap(c.path) {
				return fail(ErrTreePage)
			}
			c.path = append(c.path, page.Label...)
			f.end, f.entered = len(c.path), true
			c.active[f.id] = true
		}
		count := len(page.Children)
		if page.Tag == 4 {
			count++
		}
		if f.next == count {
			delete(c.active, f.id)
			c.stack = c.stack[:len(c.stack)-1]
			if len(c.stack) > 0 {
				c.path = c.path[:c.stack[len(c.stack)-1].end]
			} else {
				c.path = c.path[:0]
			}
			continue
		}
		next := treeWalkFrame{dirEnd: f.dirEnd, componentStart: f.componentStart}
		var edge byte
		if page.Tag == 4 && f.next == 0 {
			next.id, edge = page.Directory, '/'
			next.dirEnd, next.componentStart = f.end, f.end+1
		} else {
			i := f.next
			if page.Tag == 4 {
				i--
			}
			next.id, edge = page.Children[i].ID, page.Children[i].Edge
		}
		if len(c.stack) == c.limits.MaxDepth {
			return fail(metadata.ErrResourceExhausted)
		}
		if c.active[next.id] {
			return fail(ErrTreePage)
		}
		if len(c.path) == cap(c.path) {
			return fail(ErrTreePage)
		}
		f.next++
		c.path = append(c.path, edge)
		next.base = len(c.path)
		c.stack = append(c.stack, next)
	}
}
