//go:build darwin || linux

package model_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"canopy.local/canopy/internal/model"
	"canopy.local/canopy/internal/storage/blob"
)

// Deterministic seed: CANONICAL-READ-CAUSE-v1. The fault is returned by the
// exact source read at the specified offset, with no timing or goroutines.
type causeReader struct {
	data           []byte
	at, pos, calls int
	count          int // -2: fill buffer; -1: invalid negative; otherwise exact count
	err            error
	cancel         context.CancelFunc
	fired          bool
}

func (r *causeReader) Read(p []byte) (int, error) {
	r.calls++
	if r.fired {
		panic("decoder read again after terminal fault")
	}
	if r.pos < r.at {
		n := copy(p, r.data[r.pos:r.at])
		r.pos += n
		return n, nil
	}
	r.fired = true
	n := r.count
	if n == -2 {
		n = copy(p, r.data[r.pos:])
	} else if n >= 0 {
		copy(p, r.data[r.pos:])
	}
	if r.cancel != nil {
		r.cancel()
	}
	return n, r.err
}

func causeBlob(t *testing.T) (model.BlobID, []byte, []byte) {
	t.Helper()
	payload := []byte("CANONICAL-READ-CAUSE-v1")
	id, err := model.HashBlob(context.Background(), uint64(len(payload)), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	if err = model.EncodeBlob(context.Background(), &frame, uint64(len(payload)), bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	return id, frame.Bytes(), payload
}

func TestDecodeReadCauses(t *testing.T) {
	blobID, blobFrame, payload := causeBlob(t)
	author, err := model.NewMetadata([]byte("A"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	value, err := model.NewChangeset(model.ChangesetInput{Author: author, Message: payload})
	if err != nil {
		t.Fatal(err)
	}
	changesetID, err := model.HashChangeset(context.Background(), value)
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err = model.EncodeChangeset(context.Background(), &encoded, value); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"blob", "changeset"} {
		frame := blobFrame
		if kind == "changeset" {
			frame = encoded.Bytes()
		}
		for _, stage := range []string{"header", "payload", "final", "trailing", "negativeCount", "oversizeCount", "finalNegativeCount", "finalOversizeCount"} {
			for _, cancelled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/cancel=%t", kind, stage, cancelled), func(t *testing.T) {
					at, count := 0, -2
					data := append([]byte(nil), frame...)
					switch stage {
					case "payload":
						at = 22
					case "final":
						at = len(frame)
					case "trailing":
						at = len(frame)
						data = append(data, 0x7f)
					case "negativeCount":
						count = -1
					case "oversizeCount":
						count = 23
					case "finalNegativeCount":
						at, count = len(frame), -1
					case "finalOversizeCount":
						at, count = len(frame), 2
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					reader := &causeReader{data: data, at: at, count: count, err: syscall.EIO}
					if cancelled {
						reader.cancel = cancel
					}
					var staged bytes.Buffer
					if kind == "blob" {
						n, e := model.DecodeBlob(ctx, reader, blobID, &staged, uint64(len(payload)))
						err = e
						if n != 0 {
							t.Fatalf("invalid count escaped: %d", n)
						}
						want := 0
						if strings.HasPrefix(stage, "final") || stage == "trailing" {
							want = len(payload)
						}
						if staged.Len() != want {
							t.Fatalf("forwarded failed-read bytes: %d want %d", staged.Len(), want)
						}
					} else {
						got, e := model.DecodeChangeset(ctx, reader, changesetID, model.MaxChangesetPayload)
						err = e
						if !reflect.DeepEqual(got, model.Changeset{}) {
							t.Fatalf("invalid changeset escaped: %+v", got)
						}
					}
					if !reader.fired || !errors.Is(err, syscall.EIO) {
						t.Fatalf("source cause lost: fired=%v err=%v", reader.fired, err)
					}
					if errors.Is(err, context.Canceled) != cancelled {
						t.Fatalf("cancellation cause: %v", err)
					}
					if !cancelled && (stage == "header" || stage == "payload" || stage == "final") && err != syscall.EIO {
						t.Fatalf("lone source error identity changed: %T %v", err, err)
					}
					if (stage == "negativeCount" || stage == "oversizeCount") && !strings.Contains(err.Error(), "invalid reader count") {
						t.Fatalf("count rejection lost: %v", err)
					}
					if stage == "trailing" && !strings.Contains(err.Error(), "trailing canonical frame") {
						t.Fatalf("frame rejection lost: %v", err)
					}
					if at == 0 && reader.calls != 1 {
						t.Fatalf("unexpected reads: %d", reader.calls)
					}
				})
			}
		}
	}
}

func TestDecodeReadEOFAndCancellation(t *testing.T) {
	id, frame, payload := causeBlob(t)
	for _, at := range []int{0, 22, len(frame)} {
		for _, cause := range []error{nil, io.EOF, errors.Join(io.EOF, syscall.EIO)} {
			for _, cancelled := range []bool{false, true} {
				// A nil, uncanceled final probe has no terminal event. Bounded idle
				// handling is tested separately; this source forbids a second fault read.
				if cause == nil && !cancelled {
					continue
				}
				t.Run(fmt.Sprintf("at=%d/cause=%v/cancel=%t", at, cause, cancelled), func(t *testing.T) {
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					reader := &causeReader{data: frame, at: at, count: -2, err: cause}
					if cancelled {
						reader.cancel = cancel
					}
					var staged bytes.Buffer
					n, err := model.DecodeBlob(ctx, reader, id, &staged, uint64(len(payload)))
					success := !cancelled && cause == io.EOF && at != 0
					if success {
						if err != nil || n != uint64(len(payload)) || !bytes.Equal(staged.Bytes(), payload) {
							t.Fatalf("valid data+EOF: n=%d err=%v", n, err)
						}
					} else {
						if err == nil || n != 0 {
							t.Fatalf("false success: n=%d err=%v", n, err)
						}
						if cancelled && !errors.Is(err, context.Canceled) {
							t.Fatalf("cancel lost: %v", err)
						}
						if cancelled && (cause == nil || cause == io.EOF) && err != context.Canceled {
							t.Fatalf("lone cancellation identity changed: %T %v", err, err)
						}
						if errors.Is(cause, syscall.EIO) && !errors.Is(err, syscall.EIO) {
							t.Fatalf("wrapped source lost: %v", err)
						}
						if at <= 22 && staged.Len() != 0 {
							t.Fatalf("canceled/error bytes forwarded: %d", staged.Len())
						}
					}
				})
			}
		}
	}
	// An empty frame can legally finish with data+EOF in its header read.
	emptyID, err := model.HashBlob(context.Background(), 0, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	var empty bytes.Buffer
	if err = model.EncodeBlob(context.Background(), &empty, 0, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	r := &causeReader{data: empty.Bytes(), count: -2, err: io.EOF}
	if n, e := model.DecodeBlob(context.Background(), r, emptyID, io.Discard, 0); e != nil || n != 0 || r.calls != 1 {
		t.Fatalf("empty data+EOF: %d %v calls=%d", n, e, r.calls)
	}
}

func TestFilesystemCanonicalReadCauses(t *testing.T) {
	id, frame, payload := causeBlob(t)
	for _, at := range []int{0, 22, len(frame)} {
		for _, trailing := range []bool{false, true} {
			t.Run(fmt.Sprintf("at=%d/trailing=%t", at, trailing), func(t *testing.T) {
				root := t.TempDir()
				if err := os.Chmod(root, 0700); err != nil {
					t.Fatal(err)
				}
				store, err := blob.OpenFilesystem(root, blob.Options{MaxPayload: 1024, MaxEncodedBytes: 4096, MaxConcurrentOps: 1, RecoveryBatch: 2})
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := store.Close(); err != nil {
						t.Error(err)
					}
				}()
				for {
					done, e := store.RecoverTemps(context.Background())
					if e != nil {
						t.Fatal(e)
					}
					if done {
						break
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				data := append([]byte(nil), frame...)
				if trailing {
					data = append(data, 0x7f)
				}
				r := &causeReader{data: data, at: at, count: -2, err: syscall.EIO, cancel: cancel}
				result, err := store.Put(ctx, id, uint64(len(payload)), r)
				if result != (blob.PutResult{}) {
					t.Fatalf("false result: %+v", result)
				}
				for _, cause := range []error{blob.ErrInvalidArgument, context.Canceled, syscall.EIO} {
					if !errors.Is(err, cause) {
						t.Errorf("lost %v: %v", cause, err)
					}
				}
				entries, e := os.ReadDir(root)
				if e != nil {
					t.Fatal(e)
				}
				if len(entries) != 1 || entries[0].Name() != ".staging" {
					t.Fatalf("false final: %v", entries)
				}
				temps, e := os.ReadDir(filepath.Join(root, ".staging"))
				if e != nil || len(temps) != 0 {
					t.Fatalf("staging leftovers: %v %v", temps, e)
				}
				// A successful retry proves the failed operation released its sole slot
				// and that only a newly verified complete frame can become visible.
				result, err = store.Put(context.Background(), id, uint64(len(payload)), bytes.NewReader(frame))
				if err != nil || result.ID != id || result.Reused || result.PayloadBytes != uint64(len(payload)) {
					t.Fatalf("retry: %+v %v", result, err)
				}
				rd, err := store.OpenCanonical(context.Background(), id)
				if err != nil {
					t.Fatal(err)
				}
				got, readErr := io.ReadAll(rd)
				closeErr := rd.Close()
				if readErr != nil || closeErr != nil || !bytes.Equal(got, frame) {
					t.Fatalf("retry canonical: %x %v %v", got, readErr, closeErr)
				}
			})
		}
	}
}

type causeReaderFunc func([]byte) (int, error)

func (f causeReaderFunc) Read(p []byte) (int, error) { return f(p) }

func TestDecodeReadWorkBounds(t *testing.T) {
	id, frame, payload := causeBlob(t)
	for _, prefix := range []int{0, 22, len(frame)} {
		calls, pos := 0, 0
		r := causeReaderFunc(func(p []byte) (int, error) {
			calls++
			if pos < prefix {
				n := copy(p, frame[pos:prefix])
				pos += n
				return n, nil
			}
			return 0, nil
		})
		n, err := model.DecodeBlob(context.Background(), r, id, io.Discard, uint64(len(payload)))
		want := 100
		if prefix > 0 {
			want++
		}
		if prefix > 22 {
			want++
		}
		if n != 0 || !errors.Is(err, io.ErrNoProgress) || calls != want {
			t.Fatalf("idle bound: %d %v calls=%d want=%d", n, err, calls, want)
		}
	}
	// Budget rejection must stop after the header and produce no provisional data.
	r := &causeReader{data: frame, at: 22, count: -2, err: syscall.EIO}
	var staged bytes.Buffer
	if n, err := model.DecodeBlob(context.Background(), r, id, &staged, 0); n != 0 || err == nil || r.calls != 1 || r.fired || staged.Len() != 0 {
		t.Fatalf("budget: %d %v reads=%d", n, err, r.calls)
	}
	// Pre-cancellation must not consult the source at all.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := model.DecodeBlob(ctx, r, id, io.Discard, uint64(len(payload))); n != 0 || !errors.Is(err, context.Canceled) || r.calls != 1 {
		t.Fatalf("pre-cancel: %d %v reads=%d", n, err, r.calls)
	}
	// Cancellation on a later chunk preserves only already-staged bytes. A
	// terminal count is always zero, even after earlier provisional output.
	large := bytes.Repeat(payload, 4000)
	largeID, err := model.HashBlob(context.Background(), uint64(len(large)), bytes.NewReader(large))
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err = model.EncodeBlob(context.Background(), &encoded, uint64(len(large)), bytes.NewReader(large)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	r = &causeReader{data: encoded.Bytes(), at: 22 + 32768, count: -2, err: syscall.EIO, cancel: cancel}
	staged.Reset()
	n, err := model.DecodeBlob(ctx, r, largeID, &staged, uint64(len(large)))
	if n != 0 || !errors.Is(err, syscall.EIO) || !errors.Is(err, context.Canceled) || !bytes.Equal(staged.Bytes(), large[:32768]) {
		t.Fatalf("later canceled chunk: n=%d staged=%d err=%v", n, staged.Len(), err)
	}
}

func TestDecodeChangesetCancellationIdentity(t *testing.T) {
	value, err := model.NewChangeset(model.ChangesetInput{})
	if err != nil {
		t.Fatal(err)
	}
	id, err := model.HashChangeset(context.Background(), value)
	if err != nil {
		t.Fatal(err)
	}
	var frame bytes.Buffer
	if err = model.EncodeChangeset(context.Background(), &frame, value); err != nil {
		t.Fatal(err)
	}
	for _, at := range []int{0, 22, frame.Len()} {
		for _, cause := range []error{nil, io.EOF} {
			ctx, cancel := context.WithCancel(context.Background())
			r := &causeReader{data: frame.Bytes(), at: at, count: -2, err: cause, cancel: cancel}
			got, err := model.DecodeChangeset(ctx, r, id, model.MaxChangesetPayload)
			cancel()
			if err != context.Canceled || !reflect.DeepEqual(got, model.Changeset{}) {
				t.Fatalf("at=%d cause=%v: got=%+v err=%T %v", at, cause, got, err, err)
			}
		}
	}
}

func TestDecodeReadLoneRejectionUnwrapped(t *testing.T) {
	id, frame, payload := causeBlob(t)
	for _, at := range []int{0, len(frame)} {
		data := append(append([]byte(nil), frame...), 0x7f)
		count := -1
		if at != 0 {
			count = 1
		}
		r := &causeReader{data: data, at: at, count: count}
		n, err := model.DecodeBlob(context.Background(), r, id, io.Discard, uint64(len(payload)))
		if n != 0 || err == nil {
			t.Fatalf("rejection escaped: %d %v", n, err)
		}
		if _, wrapped := err.(interface{ Unwrap() []error }); wrapped {
			t.Fatalf("lone rejection wrapped: %T %v", err, err)
		}
		if errors.Unwrap(err) != nil {
			t.Fatalf("lone rejection wrapped: %v", err)
		}
	}
}
