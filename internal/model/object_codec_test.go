package model

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// frozenVectors is the independent literal oracle frozen by accepted OBJ-01-A
// in object_types_test.go. Its source is pinned in tests/provenance.json.
func TestEncodeAndHashFrozenCanonicalVectors(t *testing.T) {
	for _, vector := range frozenVectors {
		t.Run(vector.name, func(t *testing.T) {
			want := unhex(t, vector.preimage)
			digest := encodeTestDigest(t, vector.digest)
			var output bytes.Buffer
			var gotDigest [32]byte
			var gotKind ObjectKind
			if vector.name == "blob_empty" || vector.name == "blob_x" {
				payload := []byte(nil)
				if vector.name == "blob_x" {
					payload = []byte{'x'}
				}
				if err := EncodeBlob(context.Background(), &output, uint64(len(payload)), bytes.NewReader(payload)); err != nil {
					t.Fatal(err)
				}
				id, err := HashBlob(context.Background(), uint64(len(payload)), bytes.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				gotDigest, gotKind = id.TypedID().Digest(), id.TypedID().Kind()
			} else {
				value := encodeTestChangesetForVector(t, vector.name)
				if err := EncodeChangeset(context.Background(), &output, value); err != nil {
					t.Fatal(err)
				}
				id, err := HashChangeset(context.Background(), value)
				if err != nil {
					t.Fatal(err)
				}
				gotDigest, gotKind = id.TypedID().Digest(), id.TypedID().Kind()
			}
			if !bytes.Equal(output.Bytes(), want) {
				t.Fatalf("canonical frame mismatch\n got %x\nwant %x", output.Bytes(), want)
			}
			if gotDigest != digest || gotKind != ObjectKind(want[13]) {
				t.Fatalf("typed digest mismatch: kind=%d digest=%x want=%d/%x", gotKind, gotDigest, want[13], digest)
			}
			if len(want) < 22 || binary.BigEndian.Uint64(want[14:22]) != uint64(len(want)-22) {
				t.Fatalf("literal frame length is inconsistent: %d bytes", len(want))
			}
		})
	}
}

func TestChangesetOrderAndSimultaneousDelta(t *testing.T) {
	t.Run("duplicate-parent-literal", func(t *testing.T) {
		input := ChangesetInput{Parents: []ChangesetID{parentA(t), parentA(t)}, Author: metadata(t, []byte("A"), 0, 0)}
		value, err := NewChangeset(input)
		if err != nil {
			t.Fatal(err)
		}
		// Independent literal: canonical payload with the same accepted parent
		// TID twice; SHA-256 is then checked over these fixed bytes.
		want := unhex(t, "43414e4f5059004f424a0000010200000000000000730000000000000000000000000000000000000002000102f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee000102f6737fd55f7bd71004146b225ab018e6146aee88859063fe5064c0dd83973eee00000001410000000000000000000000000000000000000000")
		var output bytes.Buffer
		if err := EncodeChangeset(context.Background(), &output, value); err != nil {
			t.Fatal(err)
		}
		id, err := HashChangeset(context.Background(), value)
		if err != nil || !bytes.Equal(output.Bytes(), want) || id.TypedID().Digest() != sha256.Sum256(want) {
			t.Fatalf("duplicate parent sequence changed: err=%v digest=%x", err, id.TypedID().Digest())
		}
		// Repo identity is opaque and identity-bearing. Replace only the 16
		// literal repo bytes in the independent preimage, never encoder output.
		input.RepoID = [16]byte{0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		copy(want[22:38], input.RepoID[:])
		value, err = NewChangeset(input)
		if err != nil {
			t.Fatal(err)
		}
		output.Reset()
		if err := EncodeChangeset(context.Background(), &output, value); err != nil {
			t.Fatal(err)
		}
		id, err = HashChangeset(context.Background(), value)
		if err != nil || !bytes.Equal(output.Bytes(), want) || id.TypedID().Digest() != sha256.Sum256(want) {
			t.Fatalf("repository identity changed: err=%v digest=%x", err, id.TypedID().Digest())
		}
	})

	t.Run("sorted-prefix-delta-is-encodable", func(t *testing.T) {
		remove := operation(t, []byte("a"), Delete)
		setChild := operation(t, []byte("a/b"), SetRegular)
		value, err := NewChangeset(ChangesetInput{Operations: []Operation{remove, setChild}})
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := EncodeChangeset(context.Background(), &output, value); err != nil {
			t.Fatalf("sorted prefix operations are a simultaneous delta: %v", err)
		}
		if output.Len() != 22+int(value.PayloadSize()) {
			t.Fatalf("wrong exact frame length: %d", output.Len())
		}
	})
}

func TestChangesetInvalidValuesFailBeforeOutput(t *testing.T) {
	t.Run("invalid-path-and-zero-hash", func(t *testing.T) {
		value := encodeTestChangesetForVector(t, "mode_regular")
		value.value.Operations[0].path = Path{raw: "."} // same length, invalid path
		var output bytes.Buffer
		err := EncodeChangeset(context.Background(), &output, value)
		id, hashErr := HashChangeset(context.Background(), value)
		if err == nil || output.Len() != 0 || hashErr == nil || id != (ChangesetID{}) {
			t.Fatalf("invalid path effects: encode=%v output=%d hash=%v id=%v", err, output.Len(), hashErr, id)
		}
	})

	t.Run("out-of-order-operations", func(t *testing.T) {
		input := ChangesetInput{Author: metadata(t, []byte("A"), 0, 0), Operations: []Operation{
			operation(t, []byte("b"), SetRegular), operation(t, []byte("a"), SetRegular),
		}}
		value := Changeset{value: input} // malformed internal value to exercise encoder preflight
		var output bytes.Buffer
		if err := EncodeChangeset(context.Background(), &output, value); err == nil || output.Len() != 0 {
			t.Fatalf("out-of-order operations were emitted: err=%v bytes=%d", err, output.Len())
		}
	})

	t.Run("unconstructed-zero-value", func(t *testing.T) {
		var output bytes.Buffer
		if err := EncodeChangeset(context.Background(), &output, Changeset{}); err == nil || output.Len() != 0 {
			t.Fatalf("zero value reached output: err=%v bytes=%d", err, output.Len())
		}
	})
}

func TestBlobStreamingAndBounds(t *testing.T) {
	t.Run("bounded-multichunk-stream", func(t *testing.T) {
		length := uint64(4*(32<<10) + 17)
		reader, writer := &encodeTestZeroReader{remaining: length, chunk: 17}, &encodeTestObservedWriter{}
		if err := EncodeBlob(context.Background(), writer, length, reader); err != nil {
			t.Fatal(err)
		}
		if reader.total != length || reader.maxRequest > 32<<10 || writer.maxWrite > 32<<10 {
			t.Fatalf("unbounded/incomplete stream: read=%d max-read=%d max-write=%d", reader.total, reader.maxRequest, writer.maxWrite)
		}
		frame := writer.data.Bytes()
		if uint64(len(frame)) != 22+length || binary.BigEndian.Uint64(frame[14:22]) != length {
			t.Fatalf("wrong exact frame length: %d", len(frame))
		}
		want := append(frame[:22:22], make([]byte, int(length))...)
		if !bytes.Equal(frame, want) {
			t.Fatal("streamed payload changed")
		}
		id, err := HashBlob(context.Background(), length, &encodeTestZeroReader{remaining: length})
		if err != nil || id.TypedID().Digest() != sha256.Sum256(frame) {
			t.Fatalf("stream hash mismatch: id=%x err=%v", id.TypedID().Digest(), err)
		}
	})

	t.Run("over-limit-preflight", func(t *testing.T) {
		reader, writer := &encodeTestNoProgressReader{}, &encodeTestObservedWriter{}
		err := EncodeBlob(context.Background(), writer, MaxBlobPayload+1, reader)
		if err == nil || reader.calls != 0 || writer.data.Len() != 0 {
			t.Fatalf("over-limit input had effects: err=%v reads=%d writes=%d", err, reader.calls, writer.data.Len())
		}
		id, err := HashBlob(context.Background(), MaxBlobPayload+1, reader)
		if err == nil || id != (BlobID{}) || reader.calls != 0 {
			t.Fatalf("over-limit hash had effects: id=%v err=%v reads=%d", id, err, reader.calls)
		}
	})

	t.Run("maximum-declaration-streams-bounded", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		reader, writer := &encodeTestCancelOnRead{cancel: cancel}, &encodeTestObservedWriter{}
		err := EncodeBlob(ctx, writer, MaxBlobPayload, reader)
		if !errors.Is(err, context.Canceled) || reader.calls != 1 || reader.maxRequest > 32<<10 {
			t.Fatalf("maximum accepted payload was rejected or read unbounded: err=%v calls=%d max=%d", err, reader.calls, reader.maxRequest)
		}
		if writer.data.Len() != 22 || binary.BigEndian.Uint64(writer.data.Bytes()[14:22]) != MaxBlobPayload {
			t.Fatalf("unexpected output before bounded cancellation: %d bytes", writer.data.Len())
		}
	})
}

func TestBlobReadWriteFailuresAndCancellation(t *testing.T) {
	boom := errors.New("injected I/O failure")
	cases := []struct {
		name string
		n    uint64
		r    io.Reader
		want error
	}{
		{"short", 2, bytes.NewReader([]byte{1}), io.ErrUnexpectedEOF},
		{"excess", 1, bytes.NewReader([]byte{1, 2}), nil},
		{"reader-error-with-data", 2, &encodeTestReadOnce{data: []byte{1}, err: boom}, boom},
		{"no-progress", 1, &encodeTestNoProgressReader{}, io.ErrNoProgress},
		{"invalid-reader-count", 1, encodeTestBadCountReader{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := HashBlob(context.Background(), tc.n, tc.r)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || id != (BlobID{}) {
				t.Fatalf("failure returned id=%v err=%v want=%v", id, err, tc.want)
			}
		})
	}

	t.Run("failing-writer", func(t *testing.T) {
		writer := &encodeTestWriter{limit: 23, err: boom}
		if err := EncodeBlob(context.Background(), writer, 2, bytes.NewReader([]byte{1, 2})); !errors.Is(err, boom) {
			t.Fatalf("writer error lost: %v", err)
		}
	})
	t.Run("short-writer", func(t *testing.T) {
		if err := EncodeBlob(context.Background(), encodeTestShortWriter{}, 1, bytes.NewReader([]byte{1})); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write lost: %v", err)
		}
	})
	t.Run("pre-canceled-no-effects", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		reader, writer := &encodeTestNoProgressReader{}, &encodeTestObservedWriter{}
		err := EncodeBlob(ctx, writer, 1, reader)
		if !errors.Is(err, context.Canceled) || reader.calls != 0 || writer.data.Len() != 0 {
			t.Fatalf("pre-cancellation effects: err=%v reads=%d writes=%d", err, reader.calls, writer.data.Len())
		}
	})
	t.Run("cancel-after-final-read-zero-id", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		id, err := HashBlob(ctx, 3, &encodeTestReadOnce{data: []byte{1, 2, 3}, err: io.EOF, after: cancel})
		if !errors.Is(err, context.Canceled) || id != (BlobID{}) {
			t.Fatalf("final-read cancellation returned id=%v err=%v", id, err)
		}
	})
	t.Run("exact-final-read-with-eof", func(t *testing.T) {
		writer := &encodeTestObservedWriter{}
		err := EncodeBlob(context.Background(), writer, 3, &encodeTestReadOnce{data: []byte{1, 2, 3}, err: io.EOF})
		if err != nil || writer.data.Len() != 25 {
			t.Fatalf("exact EOF read failed: bytes=%d err=%v", writer.data.Len(), err)
		}
	})
}

func TestChangesetWriterAndFinalCancellationFailures(t *testing.T) {
	value := encodeTestChangesetForVector(t, "metadata_absent")
	t.Run("failing-writer", func(t *testing.T) {
		boom := errors.New("changeset output failed")
		if err := EncodeChangeset(context.Background(), &encodeTestWriter{limit: 23, err: boom}, value); !errors.Is(err, boom) {
			t.Fatalf("changeset writer error lost: %v", err)
		}
	})
	t.Run("short-writer", func(t *testing.T) {
		if err := EncodeChangeset(context.Background(), encodeTestShortWriter{}, value); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("changeset short write lost: %v", err)
		}
	})
	t.Run("cancel-on-final-write-and-zero-id", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var written uint64
		writer := encodeTestWriteFunc(func(p []byte) (int, error) {
			written += uint64(len(p))
			if written == 22+value.PayloadSize() {
				cancel()
			}
			return len(p), nil
		})
		if err := EncodeChangeset(ctx, writer, value); !errors.Is(err, context.Canceled) || written != 22+value.PayloadSize() {
			t.Fatalf("final-write cancellation lost: bytes=%d err=%v", written, err)
		}
		id, err := HashChangeset(ctx, value)
		if !errors.Is(err, context.Canceled) || id != (ChangesetID{}) {
			t.Fatalf("cancellation returned id=%v err=%v", id, err)
		}
	})
}

func encodeTestChangesetForVector(t *testing.T, name string) Changeset {
	t.Helper()
	input := ChangesetInput{Author: metadata(t, []byte("A"), 0, 0)}
	switch name {
	case "root_A_message_ff":
		input.Message = []byte{0xff}
	case "nonutf8_ff_executable_parent_A":
		input.Parents, input.Operations = []ChangesetID{parentA(t)}, []Operation{operation(t, []byte{0xff}, SetExecutable)}
	case "delete_ff_parent_B":
		input.Parents, input.Operations = []ChangesetID{parentB(t)}, []Operation{operation(t, []byte{0xff}, Delete)}
	case "noop_delete_ff_root":
		input.Operations = []Operation{operation(t, []byte{0xff}, Delete)}
	case "parent_order_AB":
		input.Parents = []ChangesetID{parentA(t), parentB(t)}
	case "parent_order_BA":
		input.Parents = []ChangesetID{parentB(t), parentA(t)}
	case "mode_regular":
		input.Operations = []Operation{operation(t, []byte("f"), SetRegular)}
	case "mode_executable":
		input.Operations = []Operation{operation(t, []byte("f"), SetExecutable)}
	case "mode_symlink":
		input.Operations = []Operation{operation(t, []byte("f"), SetSymlink)}
	case "committer_present_empty":
		m := metadata(t, nil, 0, 0)
		input.Committer = &m
	case "encoding_present_empty":
		input.Encoding = []byte{}
	case "metadata_full_offsets":
		input.Author = metadata(t, []byte("A"), 1700000000, 330)
		m := metadata(t, []byte("C"), 1700000007, -300)
		input.Committer, input.Message, input.Encoding = &m, []byte("m"), []byte("utf-8")
	case "path_A_upper":
		input.Operations = []Operation{operation(t, []byte("A"), SetRegular)}
	case "path_a_lower":
		input.Operations = []Operation{operation(t, []byte("a"), SetRegular)}
	case "path_nfc_e_acute":
		input.Operations = []Operation{operation(t, []byte{0xc3, 0xa9}, SetRegular)}
	case "path_nfd_e_acute":
		input.Operations = []Operation{operation(t, []byte{0x65, 0xcc, 0x81}, SetRegular)}
	case "metadata_absent":
	default:
		t.Fatalf("unknown frozen vector: %s", name)
	}
	value, err := NewChangeset(input)
	if err != nil {
		t.Fatalf("invalid vector changeset: %v", err)
	}
	return value
}

func encodeTestDigest(t *testing.T, rawHex string) [32]byte {
	t.Helper()
	raw := unhex(t, rawHex)
	if len(raw) != 32 {
		t.Fatalf("expected 32-byte digest, got %d", len(raw))
	}
	var digest [32]byte
	copy(digest[:], raw)
	return digest
}

type encodeTestObservedWriter struct {
	data     bytes.Buffer
	maxWrite int
}

func (w *encodeTestObservedWriter) Write(p []byte) (int, error) {
	if len(p) > w.maxWrite {
		w.maxWrite = len(p)
	}
	return w.data.Write(p)
}

type encodeTestZeroReader struct {
	remaining, total uint64
	maxRequest       int
	chunk            int
}

func (r *encodeTestZeroReader) Read(p []byte) (int, error) {
	if len(p) > r.maxRequest {
		r.maxRequest = len(p)
	}
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if r.chunk != 0 && n > r.chunk {
		n = r.chunk
	}
	if uint64(n) > r.remaining {
		n = int(r.remaining)
	}
	clear(p[:n])
	r.remaining -= uint64(n)
	r.total += uint64(n)
	return n, nil
}

type encodeTestNoProgressReader struct{ calls int }

func (r *encodeTestNoProgressReader) Read([]byte) (int, error) { r.calls++; return 0, nil }

type encodeTestBadCountReader struct{}

func (encodeTestBadCountReader) Read(p []byte) (int, error) { return len(p) + 1, nil }

type encodeTestCancelOnRead struct {
	cancel            context.CancelFunc
	calls, maxRequest int
}

func (r *encodeTestCancelOnRead) Read(p []byte) (int, error) {
	r.calls++
	if len(p) > r.maxRequest {
		r.maxRequest = len(p)
	}
	r.cancel()
	return 0, nil
}

type encodeTestReadOnce struct {
	data  []byte
	err   error
	after func()
	done  bool
}

func (r *encodeTestReadOnce) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	n := copy(p, r.data)
	if r.after != nil {
		r.after()
	}
	return n, r.err
}

type encodeTestWriter struct {
	data  bytes.Buffer
	limit int
	err   error
	short bool
}

func (w *encodeTestWriter) Write(p []byte) (int, error) {
	if w.short && len(p) > 0 {
		return len(p) - 1, nil
	}
	if w.err != nil && w.data.Len()+len(p) > w.limit {
		n := w.limit - w.data.Len()
		if n < 0 {
			n = 0
		}
		w.data.Write(p[:n])
		return n, w.err
	}
	return w.data.Write(p)
}

type encodeTestShortWriter struct{}

func (encodeTestShortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

type encodeTestWriteFunc func([]byte) (int, error)

func (f encodeTestWriteFunc) Write(p []byte) (int, error) { return f(p) }
