package model

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"testing"
)

// These tests consume the accepted literal frames in object_types_test.go.
// The local frame helper gives constructed and malformed payloads a matching
// digest. Frozen literal frames remain the independent expected oracle.
func decodeTestFrame(t *testing.T, kind ObjectKind, payload []byte) ([]byte, TypedID) {
	t.Helper()
	frame := make([]byte, 22+len(payload))
	copy(frame, []byte("CANOPY\x00OBJ\x00"))
	binary.BigEndian.PutUint16(frame[11:13], CanonicalVersion)
	frame[13] = byte(kind)
	binary.BigEndian.PutUint64(frame[14:22], uint64(len(payload)))
	copy(frame[22:], payload)
	sum := sha256.Sum256(frame)
	id, err := NewTypedID(kind, sum)
	if err != nil {
		t.Fatal(err)
	}
	return frame, id
}

func decodeTestLiteral(t *testing.T, name string) []byte {
	t.Helper()
	for _, v := range frozenVectors {
		if v.name == name {
			return unhex(t, v.preimage)
		}
	}
	t.Fatalf("missing frozen vector %q", name)
	return nil
}

func decodeTestTID(t *testing.T, name string) []byte {
	t.Helper()
	for _, v := range frozenVectors {
		if v.name == name {
			return unhex(t, v.tid)
		}
	}
	t.Fatalf("missing frozen vector ID %q", name)
	return nil
}

func decodeTestBadChangeset(t *testing.T, payload []byte) {
	t.Helper()
	frame, typed := decodeTestFrame(t, ChangesetKind, payload)
	id, err := NewChangesetID(typed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeChangeset(context.Background(), bytes.NewReader(frame), id, MaxChangesetPayload)
	if err == nil || !reflect.DeepEqual(got, Changeset{}) {
		t.Fatalf("malformed changeset escaped: result=%+v err=%v", got, err)
	}
}

func TestDecodeIndependentLiteralFrames(t *testing.T) {
	for _, v := range frozenVectors {
		t.Run(v.name, func(t *testing.T) {
			frame := unhex(t, v.preimage)
			payload := frame[22:]
			tid := unhex(t, v.tid)
			if frame[13] == byte(BlobKind) {
				id, err := ParseBlobID(tid)
				if err != nil {
					t.Fatal(err)
				}
				var staged bytes.Buffer
				n, err := DecodeBlob(context.Background(), bytes.NewReader(frame), id, &staged, MaxBlobPayload)
				if err != nil || n != uint64(len(payload)) || !bytes.Equal(staged.Bytes(), payload) {
					t.Fatalf("blob mismatch: bytes=%x n=%d err=%v", staged.Bytes(), n, err)
				}
				return
			}
			id, err := ParseChangesetID(tid)
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodeChangeset(context.Background(), bytes.NewReader(frame), id, MaxChangesetPayload)
			if err != nil {
				t.Fatal(err)
			}
			if err := got.Validate(); err != nil || got.PayloadSize() != uint64(len(payload)) {
				t.Fatalf("invalid decoded value: size=%d err=%v", got.PayloadSize(), err)
			}
			if actual := observedPreimage(t, got.Snapshot()); !bytes.Equal(actual, frame) {
				t.Fatalf("changeset bytes changed: got %x want %x", actual, frame)
			}
			switch v.name {
			case "nonutf8_ff_executable_parent_A":
				s := got.Snapshot()
				if len(s.Operations) != 1 || !bytes.Equal(s.Operations[0].Path().Bytes(), []byte{0xff}) || s.Operations[0].Tag() != SetExecutable {
					t.Fatal("raw non-UTF8 path or executable tag changed")
				}
			case "delete_ff_parent_B", "noop_delete_ff_root":
				s := got.Snapshot()
				if len(s.Operations) != 1 || s.Operations[0].Tag() != Delete {
					t.Fatal("DELETE was not preserved")
				}
				if _, present := s.Operations[0].Target(); present {
					t.Fatal("DELETE acquired a target")
				}
			case "parent_order_AB", "parent_order_BA":
				s := got.Snapshot()
				want := []ChangesetID{parentA(t), parentB(t)}
				if v.name == "parent_order_BA" {
					want[0], want[1] = want[1], want[0]
				}
				if !reflect.DeepEqual(s.Parents, want) {
					t.Fatalf("parent sequence changed: got=%v want=%v", s.Parents, want)
				}
			case "committer_present_empty":
				if s := got.Snapshot(); s.Committer == nil || len(s.Committer.Identity()) != 0 {
					t.Fatal("present-empty committer became absent or nonempty")
				}
			case "metadata_absent":
				if got.Snapshot().Committer != nil {
					t.Fatal("absent committer became present")
				}
			case "encoding_present_empty":
				if s := got.Snapshot(); s.Encoding == nil || len(s.Encoding) != 0 {
					t.Fatal("present-empty encoding became absent or nonempty")
				}
			case "mode_regular", "mode_executable", "mode_symlink":
				want := map[string]uint32{"mode_regular": 0100644, "mode_executable": 0100755, "mode_symlink": 0120000}[v.name]
				mode, ok := got.Snapshot().Operations[0].Mode()
				if !ok || mode != want {
					t.Fatalf("mode changed: got=%o ok=%v want=%o", mode, ok, want)
				}
			}
		})
	}
}

func TestDecodeConstructedChangesetRoundTrip(t *testing.T) {
	committer := metadata(t, []byte{}, -17, -1439)
	input := ChangesetInput{
		RepoID:    [16]byte{0, 1, 2, 0xff},
		Parents:   []ChangesetID{parentB(t), parentA(t), parentB(t)},
		Author:    metadata(t, []byte{0xff, 0, 0x80}, -31, 1439),
		Committer: &committer,
		Message:   []byte{0xff, 0, 'm'},
		Encoding:  []byte{},
		Operations: []Operation{
			operation(t, []byte("a"), Delete),
			operation(t, []byte("b"), SetRegular),
			operation(t, []byte("c"), SetExecutable),
			operation(t, []byte("d"), SetSymlink),
		},
	}
	value, err := NewChangeset(input)
	if err != nil {
		t.Fatal(err)
	}
	payload := observedPreimage(t, value.Snapshot())[22:]
	frame, typed := decodeTestFrame(t, ChangesetKind, payload)
	id, err := NewChangesetID(typed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeChangeset(context.Background(), bytes.NewReader(frame), id, MaxChangesetPayload)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(value.Snapshot(), got.Snapshot()) {
		t.Fatalf("changeset value changed: got=%+v want=%+v", got.Snapshot(), value.Snapshot())
	}
	if !bytes.Equal(observedPreimage(t, got.Snapshot())[22:], payload) {
		t.Fatal("round trip changed the canonical payload")
	}
}

func TestDecodeRejectsFrameCorruptionAndBounds(t *testing.T) {
	frame := decodeTestLiteral(t, "blob_x")
	id, err := ParseBlobID(decodeTestTID(t, "blob_x"))
	if err != nil {
		t.Fatal(err)
	}
	reject := func(name string, b []byte, expected BlobID, max uint64) {
		t.Helper()
		var staged bytes.Buffer
		if n, err := DecodeBlob(context.Background(), bytes.NewReader(b), expected, &staged, max); err == nil || n != 0 {
			t.Fatalf("%s: n=%d err=%v", name, n, err)
		}
	}
	for cut := 0; cut < len(frame); cut++ {
		reject("truncation", frame[:cut], id, MaxBlobPayload)
	}
	reject("trailing byte", append(append([]byte(nil), frame...), 0), id, MaxBlobPayload)
	for _, mutate := range []struct {
		name string
		at   int
		b    byte
	}{{"magic", 0, 'X'}, {"version", 12, 2}, {"kind", 13, 9}, {"digest", len(frame) - 1, 'y'}} {
		bad := append([]byte(nil), frame...)
		bad[mutate.at] = mutate.b
		reject(mutate.name, bad, id, MaxBlobPayload)
	}
	short := append([]byte(nil), frame...)
	binary.BigEndian.PutUint64(short[14:22], 0)
	reject("contradictory short length", short, id, MaxBlobPayload)
	large := append([]byte(nil), frame[:22]...)
	binary.BigEndian.PutUint64(large[14:22], MaxBlobPayload+1)
	counted := &decodeTestCountingReader{r: bytes.NewReader(large)}
	var staged bytes.Buffer
	if n, err := DecodeBlob(context.Background(), counted, id, &staged, MaxBlobPayload); err == nil || n != 0 || counted.n > 22 {
		t.Fatalf("oversize declaration was admitted: n=%d read=%d err=%v", n, counted.n, err)
	}
	reject("application byte budget", frame, id, 0)
	empty := decodeTestLiteral(t, "blob_empty")
	emptyID, err := ParseBlobID(decodeTestTID(t, "blob_empty"))
	if err != nil {
		t.Fatal(err)
	}
	var emptyOut bytes.Buffer
	if n, err := DecodeBlob(context.Background(), bytes.NewReader(empty), emptyID, &emptyOut, 0); err != nil || n != 0 || emptyOut.Len() != 0 {
		t.Fatalf("empty payload under zero budget: n=%d bytes=%d err=%v", n, emptyOut.Len(), err)
	}
}

type decodeTestCountingReader struct {
	r io.Reader
	n int
}

func (r *decodeTestCountingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += n
	return n, err
}

func TestDecodeRejectsMalformedChangesets(t *testing.T) {
	root := append([]byte(nil), decodeTestLiteral(t, "root_A_message_ff")[22:]...)
	regular := append([]byte(nil), decodeTestLiteral(t, "mode_regular")[22:]...)
	encoding := append([]byte(nil), decodeTestLiteral(t, "encoding_present_empty")[22:]...)
	cases := []struct {
		name string
		data []byte
	}{
		{"excessive parent count", func() []byte {
			p := append([]byte(nil), root...)
			binary.BigEndian.PutUint32(p[16:20], ^uint32(0))
			return p
		}()},
		{"parent count exceeds remaining", func() []byte {
			p := append([]byte(nil), root...)
			binary.BigEndian.PutUint32(p[16:20], 1)
			return p
		}()},
		{"excessive operation count", func() []byte {
			p := append([]byte(nil), root...)
			binary.BigEndian.PutUint32(p[42:46], ^uint32(0))
			return p
		}()},
		{"operation count exceeds remaining", func() []byte {
			p := append([]byte(nil), root...)
			binary.BigEndian.PutUint32(p[42:46], 1)
			return p
		}()},
		{"author length exceeds remaining", func() []byte {
			p := append([]byte(nil), root...)
			binary.BigEndian.PutUint32(p[20:24], ^uint32(0))
			return p
		}()},
		{"in-limit author length exceeds remaining", func() []byte {
			p := append([]byte(nil), root...)
			binary.BigEndian.PutUint32(p[20:24], 100)
			return p
		}()},
		{"message length exceeds remaining", func() []byte {
			p := append([]byte(nil), root...)
			binary.BigEndian.PutUint32(p[36:40], ^uint32(0))
			return p
		}()},
		{"in-limit message length exceeds remaining", func() []byte {
			p := append([]byte(nil), root...)
			binary.BigEndian.PutUint32(p[36:40], 100)
			return p
		}()},
		{"encoding length exceeds remaining", func() []byte {
			p := append([]byte(nil), encoding...)
			binary.BigEndian.PutUint32(p[41:45], ^uint32(0))
			return p
		}()},
		{"in-limit encoding length exceeds remaining", func() []byte {
			p := append([]byte(nil), encoding...)
			binary.BigEndian.PutUint32(p[41:45], 100)
			return p
		}()},
		{"bad committer presence", func() []byte { p := append([]byte(nil), root...); p[35] = 2; return p }()},
		{"bad encoding presence", func() []byte { p := append([]byte(nil), root...); p[41] = 2; return p }()},
		{"invalid signed offset", func() []byte {
			p := append([]byte(nil), root...)
			binary.BigEndian.PutUint16(p[33:35], 0x7fff)
			return p
		}()},
		{"invalid path", func() []byte { p := append([]byte(nil), regular...); p[49] = '.'; return p }()},
		{"path length exceeds remaining", func() []byte {
			p := append([]byte(nil), regular...)
			binary.BigEndian.PutUint32(p[45:49], ^uint32(0))
			return p
		}()},
		{"in-limit path length exceeds remaining", func() []byte {
			p := append([]byte(nil), regular...)
			binary.BigEndian.PutUint32(p[45:49], 100)
			return p
		}()},
		{"unknown operation tag", func() []byte { p := append([]byte(nil), regular...); p[50] = 4; return p }()},
		{"SET target has wrong kind", func() []byte { p := append([]byte(nil), regular...); p[53] = byte(ChangesetKind); return p }()},
		{"DELETE carries a target", func() []byte { p := append([]byte(nil), regular...); p[50] = byte(Delete); return p }()},
		{"SET target truncated", append([]byte(nil), regular[:len(regular)-35]...)},
	}
	parent := append([]byte(nil), decodeTestLiteral(t, "nonutf8_ff_executable_parent_A")[22:]...)
	parent[22] = byte(BlobKind)
	cases = append(cases, struct {
		name string
		data []byte
	}{"parent has wrong kind", parent})
	badParentVersion := append([]byte(nil), decodeTestLiteral(t, "nonutf8_ff_executable_parent_A")[22:]...)
	badParentVersion[21] = 2
	cases = append(cases, struct {
		name string
		data []byte
	}{"parent has unknown version", badParentVersion})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { decodeTestBadChangeset(t, tc.data) })
	}
	duplicate := append([]byte(nil), regular...)
	binary.BigEndian.PutUint32(duplicate[41:45], 2)
	duplicate = append(duplicate, regular[45:]...)
	t.Run("duplicate operation path", func(t *testing.T) { decodeTestBadChangeset(t, duplicate) })
	ordered := append([]byte(nil), regular...)
	ordered[49] = 'b'
	binary.BigEndian.PutUint32(ordered[41:45], 2)
	second := append([]byte(nil), regular[45:]...)
	second[4] = 'a'
	ordered = append(ordered, second...)
	t.Run("out of order operation paths", func(t *testing.T) { decodeTestBadChangeset(t, ordered) })
	pair := []struct {
		path []byte
		tag  OperationTag
	}{{[]byte("a"), SetRegular}, {[]byte("a/b"), SetRegular}}
	blob := blobX(t)
	first, _ := NewOperation(path(t, pair[0].path), pair[0].tag, &blob)
	secondOp, _ := NewOperation(path(t, pair[1].path), pair[1].tag, &blob)
	input := ChangesetInput{Author: metadata(t, []byte("A"), 0, 0), Operations: []Operation{first, secondOp}}
	value, err := NewChangeset(input)
	if err != nil {
		t.Fatal(err)
	}
	frame, typed := decodeTestFrame(t, ChangesetKind, observedPreimage(t, value.Snapshot())[22:])
	id, err := NewChangesetID(typed)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeChangeset(context.Background(), bytes.NewReader(frame), id, MaxChangesetPayload); err == nil || !reflect.DeepEqual(got, Changeset{}) {
		t.Fatalf("SET ancestor conflict escaped: result=%+v err=%v", got, err)
	}
	largePayload := append([]byte(nil), root...)
	largeFrame, largeTyped := decodeTestFrame(t, ChangesetKind, largePayload)
	largeID, err := NewChangesetID(largeTyped)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeChangeset(context.Background(), bytes.NewReader(largeFrame), largeID, uint64(len(largePayload)-1)); err == nil || !reflect.DeepEqual(got, Changeset{}) {
		t.Fatalf("caller payload budget was ignored: result=%+v err=%v", got, err)
	}
}

func TestDecodeRejectsChangesetFrameCorruptionAndBounds(t *testing.T) {
	frame := decodeTestLiteral(t, "root_A_message_ff")
	id, err := ParseChangesetID(decodeTestTID(t, "root_A_message_ff"))
	if err != nil {
		t.Fatal(err)
	}
	reject := func(name string, b []byte, max uint64) {
		t.Helper()
		got, err := DecodeChangeset(context.Background(), bytes.NewReader(b), id, max)
		if err == nil || !reflect.DeepEqual(got, Changeset{}) {
			t.Fatalf("%s: result=%+v err=%v", name, got, err)
		}
	}
	for cut := 0; cut < len(frame); cut++ {
		reject("truncation", frame[:cut], MaxChangesetPayload)
	}
	reject("trailing byte", append(append([]byte(nil), frame...), 0), MaxChangesetPayload)
	for _, mutate := range []struct {
		name string
		at   int
		b    byte
	}{{"magic", 0, 'X'}, {"version", 12, 2}, {"kind", 13, 9}, {"digest", 22 + 40, 'y'}} {
		bad := append([]byte(nil), frame...)
		bad[mutate.at] = mutate.b
		reject(mutate.name, bad, MaxChangesetPayload)
	}
	short := append([]byte(nil), frame...)
	binary.BigEndian.PutUint64(short[14:22], 0)
	reject("contradictory short length", short, MaxChangesetPayload)
	large := append([]byte(nil), frame[:22]...)
	binary.BigEndian.PutUint64(large[14:22], MaxChangesetPayload+1)
	counted := &decodeTestCountingReader{r: bytes.NewReader(large)}
	if got, err := DecodeChangeset(context.Background(), counted, id, MaxChangesetPayload); err == nil || !reflect.DeepEqual(got, Changeset{}) || counted.n > 22 {
		t.Fatalf("oversize declaration was admitted: result=%+v read=%d err=%v", got, counted.n, err)
	}
	reject("caller byte budget", frame, uint64(len(frame[22:])-1))
}

type decodeTestErrReader struct {
	data     []byte
	pos      int
	splitAt  int
	finalErr error
	returned bool
}

type decodeTestEOFReader struct {
	data    []byte
	pos     int
	splitAt int
}

func (r *decodeTestEOFReader) Read(p []byte) (int, error) {
	if r.pos < r.splitAt {
		end := r.splitAt
		if end-r.pos > len(p) {
			end = r.pos + len(p)
		}
		n := copy(p, r.data[r.pos:end])
		r.pos += n
		return n, nil
	}
	if r.pos < len(r.data) {
		n := copy(p, r.data[r.pos:])
		r.pos += n
		if r.pos == len(r.data) {
			return n, io.EOF
		}
		return n, nil
	}
	return 0, io.EOF
}

type decodeTestCancelEOFReader struct {
	data    []byte
	pos     int
	splitAt int
	cancel  context.CancelFunc
}

func (r *decodeTestCancelEOFReader) Read(p []byte) (int, error) {
	if r.pos < r.splitAt {
		end := r.splitAt
		if end-r.pos > len(p) {
			end = r.pos + len(p)
		}
		n := copy(p, r.data[r.pos:end])
		r.pos += n
		return n, nil
	}
	if r.pos < len(r.data) {
		n := copy(p, r.data[r.pos:])
		r.pos += n
		if r.pos == len(r.data) {
			r.cancel()
			return n, io.EOF
		}
		return n, nil
	}
	r.cancel()
	return 0, io.EOF
}

type decodeTestNoProgressReader struct{}

func (decodeTestNoProgressReader) Read([]byte) (int, error) { return 0, nil }

type decodeTestBadCountReader struct{}

func (decodeTestBadCountReader) Read(p []byte) (int, error) { return len(p) + 1, nil }

type decodeTestChunkReader struct {
	r     io.Reader
	max   int
	calls int
}

func (r *decodeTestChunkReader) Read(p []byte) (int, error) {
	if len(p) > r.max {
		p = p[:r.max]
	}
	n, err := r.r.Read(p)
	if n > 0 {
		r.calls++
	}
	return n, err
}

type decodeTestChunkWriter struct {
	bytes.Buffer
	calls    int
	maxWrite int
}

func (w *decodeTestChunkWriter) Write(p []byte) (int, error) {
	w.calls++
	if len(p) > w.maxWrite {
		w.maxWrite = len(p)
	}
	return w.Buffer.Write(p)
}

func (r *decodeTestErrReader) Read(p []byte) (int, error) {
	if r.pos < r.splitAt {
		end := r.splitAt
		if end > len(r.data) {
			end = len(r.data)
		}
		if end-r.pos > len(p) {
			end = r.pos + len(p)
		}
		n := copy(p, r.data[r.pos:end])
		r.pos += n
		return n, nil
	}
	if !r.returned {
		r.returned = true
		n := copy(p, r.data[r.pos:])
		r.pos += n
		return n, r.finalErr
	}
	return 0, r.finalErr
}

type decodeTestErrWriter struct{ err error }

func (w decodeTestErrWriter) Write([]byte) (int, error) { return 0, w.err }

type decodeTestCancelWriter struct{ cancel context.CancelFunc }

func (w decodeTestCancelWriter) Write(p []byte) (int, error) {
	w.cancel()
	return len(p), nil
}

type decodeTestShortWriter struct{}

func (decodeTestShortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

type decodeTestNoProgressWriter struct{}

func (decodeTestNoProgressWriter) Write([]byte) (int, error) { return 0, nil }

func TestDecodeEOFWithFinalBytes(t *testing.T) {
	frame := decodeTestLiteral(t, "blob_x")
	id, err := ParseBlobID(decodeTestTID(t, "blob_x"))
	if err != nil {
		t.Fatal(err)
	}
	var staged bytes.Buffer
	n, err := DecodeBlob(context.Background(), &decodeTestEOFReader{data: frame, splitAt: 22}, id, &staged, MaxBlobPayload)
	if err != nil || n != 1 || !bytes.Equal(staged.Bytes(), []byte("x")) {
		t.Fatalf("EOF with final payload bytes failed: n=%d bytes=%x err=%v", n, staged.Bytes(), err)
	}
	frame = decodeTestLiteral(t, "root_A_message_ff")
	changesetID, err := ParseChangesetID(decodeTestTID(t, "root_A_message_ff"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeChangeset(context.Background(), &decodeTestEOFReader{data: frame, splitAt: 22}, changesetID, MaxChangesetPayload); err != nil || got.PayloadSize() != uint64(len(frame)-22) {
		t.Fatalf("changeset EOF with final bytes failed: size=%d err=%v", got.PayloadSize(), err)
	}
}

func TestDecodeStreamsBlobAcrossBoundedChunks(t *testing.T) {
	payload := make([]byte, 96<<10)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	frame, typed := decodeTestFrame(t, BlobKind, payload)
	id, err := NewBlobID(typed)
	if err != nil {
		t.Fatal(err)
	}
	source := &decodeTestChunkReader{r: bytes.NewReader(frame), max: 7 << 10}
	staged := &decodeTestChunkWriter{}
	n, err := DecodeBlob(context.Background(), source, id, staged, MaxBlobPayload)
	if err != nil || n != uint64(len(payload)) || !bytes.Equal(staged.Bytes(), payload) || source.calls < 2 || staged.calls < 2 || staged.maxWrite > 32768 {
		t.Fatalf("chunked stream mismatch: bytes=%d reads=%d writes=%d maxwrite=%d err=%v", n, source.calls, staged.calls, staged.maxWrite, err)
	}
}

func TestDecodeCancellationAndStreamingErrors(t *testing.T) {
	frame := decodeTestLiteral(t, "blob_x")
	id, err := ParseBlobID(decodeTestTID(t, "blob_x"))
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("injected stream failure")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var staged bytes.Buffer
	if n, err := DecodeBlob(ctx, bytes.NewReader(frame), id, &staged, MaxBlobPayload); err == nil || n != 0 {
		t.Fatalf("pre-cancelled decode escaped: n=%d err=%v", n, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	if n, err := DecodeBlob(ctx, bytes.NewReader(frame), id, decodeTestCancelWriter{cancel: cancel}, MaxBlobPayload); err == nil || n != 0 {
		t.Fatalf("cancel after provisional write escaped: n=%d err=%v", n, err)
	}
	if n, err := DecodeBlob(context.Background(), bytes.NewReader(frame), id, decodeTestErrWriter{err: cause}, MaxBlobPayload); !errors.Is(err, cause) || n != 0 {
		t.Fatalf("writer failure lost: n=%d err=%v", n, err)
	}
	for _, tc := range []struct {
		name   string
		writer io.Writer
	}{{"short write", decodeTestShortWriter{}}, {"no progress", decodeTestNoProgressWriter{}}} {
		if n, err := DecodeBlob(context.Background(), bytes.NewReader(frame), id, tc.writer, MaxBlobPayload); err == nil || n != 0 {
			t.Fatalf("%s escaped: n=%d err=%v", tc.name, n, err)
		}
	}
	reader := &decodeTestErrReader{data: frame, splitAt: 22, finalErr: cause}
	if n, err := DecodeBlob(context.Background(), reader, id, &staged, MaxBlobPayload); !errors.Is(err, cause) || n != 0 {
		t.Fatalf("non-EOF read failure lost: n=%d err=%v", n, err)
	}
	if n, err := DecodeBlob(context.Background(), decodeTestNoProgressReader{}, id, &staged, MaxBlobPayload); err == nil || n != 0 {
		t.Fatalf("no-progress reader escaped: n=%d err=%v", n, err)
	}
	if n, err := DecodeBlob(context.Background(), decodeTestBadCountReader{}, id, &staged, MaxBlobPayload); err == nil || n != 0 {
		t.Fatalf("invalid reader count escaped: n=%d err=%v", n, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancelReader := &decodeTestCancelEOFReader{data: frame, splitAt: 22, cancel: cancel}
	if n, err := DecodeBlob(ctx, cancelReader, id, &staged, MaxBlobPayload); err == nil || n != 0 {
		t.Fatalf("cancellation during final read escaped: n=%d err=%v", n, err)
	}
	changesetFrame := decodeTestLiteral(t, "root_A_message_ff")
	changesetID, err := ParseChangesetID(decodeTestTID(t, "root_A_message_ff"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeChangeset(context.Background(), &decodeTestErrReader{data: changesetFrame, splitAt: 22, finalErr: cause}, changesetID, MaxChangesetPayload)
	if !errors.Is(err, cause) || !reflect.DeepEqual(got, Changeset{}) {
		t.Fatalf("changeset read failure escaped: result=%+v err=%v", got, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	got, err = DecodeChangeset(ctx, &decodeTestCancelEOFReader{data: changesetFrame, splitAt: 22, cancel: cancel}, changesetID, MaxChangesetPayload)
	if err == nil || !reflect.DeepEqual(got, Changeset{}) {
		t.Fatalf("changeset cancellation during final read escaped: result=%+v err=%v", got, err)
	}
}
