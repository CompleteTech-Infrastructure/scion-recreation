package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"

	control "canopy.local/canopy/api/gen/control/v1"
	workflows "canopy.local/canopy/api/gen/workflows/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

func wireBudget() WireBudget {
	return WireBudget{MaxBytes: 2 << 20, MaxWork: 1 << 20, MaxRepeated: 1 << 20, MaxDepth: 16}
}
func wireVar(v uint64) []byte {
	var b [10]byte
	n := binary.PutUvarint(b[:], v)
	return append([]byte(nil), b[:n]...)
}
func wireField(n, typ uint64, b []byte) []byte {
	r := wireVar(n<<3 | typ)
	if typ == 2 {
		r = append(r, wireVar(uint64(len(b)))...)
	}
	return append(r, b...)
}
func wireValue(n, v uint64) []byte    { return wireField(n, 0, wireVar(v)) }
func wireJoin(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// This independent trusted schema exercises scalar wire forms that the current
// companion request descriptors do not all expose. It grants no endpoint rights.
func wireDescriptor(t testing.TB) protoreflect.MessageDescriptor {
	t.Helper()
	f := &descriptorpb.FileDescriptorProto{Name: proto.String("qualification.proto"), Package: proto.String("wiretest"), Syntax: proto.String("proto3")}
	f.EnumType = []*descriptorpb.EnumDescriptorProto{{Name: proto.String("Choice"), Value: []*descriptorpb.EnumValueDescriptorProto{{Name: proto.String("ZERO"), Number: proto.Int32(0)}, {Name: proto.String("NEG"), Number: proto.Int32(-1)}, {Name: proto.String("ONE"), Number: proto.Int32(1)}}}}
	m := &descriptorpb.DescriptorProto{Name: proto.String("Node"), OneofDecl: []*descriptorpb.OneofDescriptorProto{{Name: proto.String("pick")}}}
	kinds := []descriptorpb.FieldDescriptorProto_Type{13, 5, 4, 3, 17, 18, 8, 14, 7, 6, 2, 1, 9, 12, 13, 11, 13, 12, 11, 15, 16, 7, 6, 14}
	for i, k := range kinds {
		x := &descriptorpb.FieldDescriptorProto{Name: proto.String(string(rune('a' + i))), Number: proto.Int32(int32(i + 1)), Type: k.Enum(), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()}
		if i == 7 || i == 23 {
			x.TypeName = proto.String(".wiretest.Choice")
		}
		if k == descriptorpb.FieldDescriptorProto_TYPE_MESSAGE {
			x.TypeName = proto.String(".wiretest.Node")
		}
		if i == 14 || i == 18 || i >= 21 {
			x.Label = descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
		}
		if i == 16 || i == 17 {
			x.OneofIndex = proto.Int32(0)
		}
		m.Field = append(m.Field, x)
	}
	f.MessageType = []*descriptorpb.DescriptorProto{m}
	d, err := protodesc.NewFile(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	return d.Messages().Get(0)
}

func TestOriginalWireGeneratedWorkflow(t *testing.T) {
	ctx := context.Background()
	zero := uint64(0)
	requests := []proto.Message{
		&workflows.CreateChangeRequestRequest{Context: &control.RequestContext{ApiVersion: 1, RepositoryId: bytes.Repeat([]byte{1}, 16), RequestId: bytes.Repeat([]byte{2}, 16)}, Title: []byte{0xff, 0, 0x80}, ExpectedPolicyVersion: &zero, RelatedWork: [][]byte{{1}, {2}}},
		&workflows.AddPatchsetRequest{ChangeRequestId: &workflows.ChangeRequestId{Value: []byte("private-handle")}, ExpectedVersion: &zero},
		&workflows.GetChangeRequestRequest{ChangeRequestId: &workflows.ChangeRequestId{Value: []byte("private-handle")}},
	}
	for _, msg := range requests {
		b, err := proto.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		d := msg.ProtoReflect().Descriptor()
		if err = ValidateOriginal(ctx, b, d, wireBudget()); err != nil {
			t.Fatal(d.FullName(), err)
		}
		if err = ValidateOriginal(ctx, append(append([]byte(nil), b...), wireValue(100, 1)...), d, wireBudget()); !errors.Is(err, ErrWireInvalid) {
			t.Fatal("unknown tag", err)
		}
	}
	// Generated decoders merge duplicate messages, so validate before that loss.
	d := requests[0].ProtoReflect().Descriptor()
	for _, b := range [][]byte{wireJoin(wireField(1, 2, nil), wireField(1, 2, nil)), wireJoin(wireValue(6, 0), wireValue(6, 0)), wireField(1, 2, wireJoin(wireValue(1, 1), wireValue(1, 1)))} {
		if err := ValidateOriginal(ctx, b, d, wireBudget()); !errors.Is(err, ErrWireInvalid) {
			t.Fatal("generated duplicate accepted", err)
		}
	}
	response := (&workflows.CreateChangeRequestResponse{}).ProtoReflect().Descriptor()
	for _, b := range [][]byte{wireJoin(wireField(2, 2, nil), wireField(2, 2, nil)), wireJoin(wireField(2, 2, nil), wireField(3, 2, nil))} {
		if err := ValidateOriginal(ctx, b, response, wireBudget()); !errors.Is(err, ErrWireInvalid) {
			t.Fatal("result oneof accepted", err)
		}
	}
	// Empty structure remains valid; required application fields are not inferred.
	if err := ValidateOriginal(ctx, nil, d, wireBudget()); err != nil {
		t.Fatal(err)
	}
}

func TestOriginalWireScalarBoundaries(t *testing.T) {
	d := wireDescriptor(t)
	ctx := context.Background()
	valid := [][]byte{wireField(20, 5, bytes.Repeat([]byte{0xff}, 4)), wireField(21, 1, bytes.Repeat([]byte{0xff}, 8)), wireField(22, 2, make([]byte, 8)), wireField(23, 2, make([]byte, 16)), wireField(24, 2, wireVar(math.MaxUint64)), nil, wireValue(1, math.MaxUint32), wireValue(2, math.MaxInt32), wireValue(2, math.MaxUint64), wireValue(2, 0xffffffff80000000), wireValue(3, math.MaxUint64), wireValue(4, math.MaxUint64), wireValue(4, 1<<63), wireValue(5, math.MaxUint32), wireValue(6, math.MaxUint64), wireValue(7, 0), wireValue(7, 1), wireValue(8, 0), wireValue(8, 1), wireValue(8, math.MaxUint64), wireField(9, 5, make([]byte, 4)), wireField(10, 1, make([]byte, 8)), wireField(11, 5, []byte{0, 0, 0xc0, 0x7f}), wireField(12, 1, make([]byte, 8)), wireField(13, 2, []byte("é")), wireField(14, 2, []byte{0xff, 0x80, 0, 0x2f}), wireField(15, 2, wireJoin(wireVar(1), wireVar(math.MaxUint32))), wireJoin(wireValue(15, 1), wireField(15, 2, wireVar(2)), wireValue(15, 3)), wireField(15, 2, nil), wireField(16, 2, nil), wireValue(17, 0), wireField(18, 2, nil)}
	for i, b := range valid {
		if err := ValidateOriginal(ctx, b, d, wireBudget()); err != nil {
			t.Fatalf("valid %d %x: %v", i, b, err)
		}
	}
	invalid := map[string][]byte{
		"packed fixed32 remainder": wireField(22, 2, make([]byte, 5)), "packed fixed64 remainder": wireField(23, 2, make([]byte, 9)), "packed unknown enum": wireField(24, 2, []byte{2}), "uint32 overflow": wireValue(1, 1<<32), "int32 unsigned negative": wireValue(2, 1<<31), "int32 missing sign extension": wireValue(2, math.MaxUint32), "sint32 overflow": wireValue(5, 1<<32), "bool two": wireValue(7, 2), "enum unknown": wireValue(8, 2), "enum unsigned negative": wireValue(8, math.MaxUint32), "invalid UTF8": wireField(13, 2, []byte{0xff}),
		"zero tag": {0}, "reserved wire": {0x0e}, "group": {0x0b, 0x0c}, "unknown tag": wireValue(25, 0), "wrong scalar wire": wireField(1, 2, nil), "wrong fixed wire": wireValue(9, 1), "wrong bytes wire": wireValue(14, 1), "truncated fixed32": wireField(9, 5, make([]byte, 3)), "truncated fixed64": wireField(10, 1, make([]byte, 7)), "truncated length": {0x72, 0x02, 0x01}, "truncated varint": {0x08, 0x80}, "overlong tag": {0x88, 0, 0}, "overlong length": {0x72, 0x80, 0}, "overlong value": {0x08, 0x80, 0}, "varint overflow": append([]byte{0x18}, bytes.Repeat([]byte{0xff}, 10)...), "tag overflow": wireJoin(wireVar(1<<35), []byte{0}), "packed overflow": wireField(15, 2, wireVar(1<<32)), "packed truncated": wireField(15, 2, []byte{0x80}), "duplicate scalar": wireJoin(wireValue(1, 0), wireValue(1, 1)), "duplicate bytes": wireJoin(wireField(14, 2, nil), wireField(14, 2, nil)), "duplicate message": wireJoin(wireField(16, 2, nil), wireField(16, 2, nil)), "same oneof": wireJoin(wireValue(17, 1), wireValue(17, 2)), "different oneof": wireJoin(wireValue(17, 1), wireField(18, 2, nil)),
	}
	for name, b := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := ValidateOriginal(ctx, b, d, wireBudget()); !errors.Is(err, ErrWireInvalid) {
				t.Fatalf("%x: %v", b, err)
			}
		})
	}
}

func TestOriginalWireBoundsAndCancellation(t *testing.T) {
	ctx := context.Background()
	d := wireDescriptor(t)
	base := wireBudget()
	for _, b := range []WireBudget{{}, {MaxBytes: 2<<20 + 1, MaxWork: 1, MaxRepeated: 1, MaxDepth: 1}, {MaxBytes: 1, MaxWork: 1<<20 + 1, MaxRepeated: 1, MaxDepth: 1}, {MaxBytes: 1, MaxWork: 1, MaxRepeated: 1<<20 + 1, MaxDepth: 1}, {MaxBytes: 1, MaxWork: 1, MaxRepeated: 1, MaxDepth: 17}} {
		if err := ValidateOriginal(ctx, nil, d, b); !errors.Is(err, ErrWireInvalid) {
			t.Fatal("bad configuration", err)
		}
	}
	if err := ValidateOriginal(nil, nil, d, base); !errors.Is(err, ErrWireInvalid) {
		t.Fatal(err)
	}
	if err := ValidateOriginal(ctx, nil, nil, base); !errors.Is(err, ErrWireInvalid) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := ValidateOriginal(canceled, nil, d, base); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	raw := wireValue(1, 1)
	b := base
	b.MaxBytes = uint64(len(raw))
	if err := ValidateOriginal(ctx, raw, d, b); err != nil {
		t.Fatal(err)
	}
	b.MaxBytes--
	if err := ValidateOriginal(ctx, raw, d, b); !errors.Is(err, ErrWireLimit) {
		t.Fatal(err)
	}
	b = base
	b.MaxWork = 1
	if err := ValidateOriginal(ctx, wireValue(1, 1), d, b); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOriginal(ctx, wireJoin(wireValue(1, 1), wireValue(2, 1)), d, b); !errors.Is(err, ErrWireLimit) {
		t.Fatal(err)
	}
	b = base
	b.MaxRepeated = 2
	for _, raw := range [][]byte{wireJoin(wireValue(15, 0), wireValue(15, 1)), wireField(15, 2, []byte{0, 1})} {
		if err := ValidateOriginal(ctx, raw, d, b); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range [][]byte{wireJoin(wireValue(15, 0), wireValue(15, 1), wireValue(15, 2)), wireField(15, 2, []byte{0, 1, 2}), wireJoin(wireField(15, 2, nil), wireField(15, 2, nil), wireField(15, 2, nil))} {
		if err := ValidateOriginal(ctx, raw, d, b); !errors.Is(err, ErrWireLimit) {
			t.Fatal("repeated", err)
		}
	}
	b = base
	b.MaxWork = 3
	if err := ValidateOriginal(ctx, wireField(15, 2, []byte{1, 2}), d, b); err != nil {
		t.Fatal(err)
	}
	b.MaxWork = 2
	if err := ValidateOriginal(ctx, wireField(15, 2, []byte{1, 2}), d, b); !errors.Is(err, ErrWireLimit) {
		t.Fatal("packed work", err)
	}
	raw = nil
	for depth := 1; depth <= 17; depth++ {
		if depth > 1 {
			raw = wireField(16, 2, raw)
		}
		err := ValidateOriginal(ctx, raw, d, base)
		if depth <= 16 && err != nil || depth == 17 && !errors.Is(err, ErrWireLimit) {
			t.Fatalf("depth%d: %v", depth, err)
		}
	}
	b = base
	b.MaxDepth = 1
	if err := ValidateOriginal(ctx, wireField(16, 2, nil), d, b); !errors.Is(err, ErrWireLimit) {
		t.Fatal("empty nested", err)
	}
	// Repeated quotas are local to each message instance, not shared siblings.
	raw = wireJoin(wireField(19, 2, wireValue(15, 1)), wireField(19, 2, wireValue(15, 2)))
	b = base
	b.MaxRepeated = 2
	if err := ValidateOriginal(ctx, raw, d, b); err != nil {
		t.Fatal(err)
	}
}

type wireCancelContext struct {
	context.Context
	calls  atomic.Uint64
	cancel context.CancelFunc
}

func (c *wireCancelContext) Err() error {
	if c.calls.Add(1) == 64 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestOriginalWireMaximumAndMidWorkCancel(t *testing.T) {
	d := wireDescriptor(t)
	b := wireBudget()
	ctx := context.Background()
	raw := wireField(14, 2, make([]byte, (2<<20)-4))
	if len(raw) != 2<<20 {
		t.Fatal(len(raw))
	}
	if err := ValidateOriginal(ctx, raw, d, b); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOriginal(ctx, append(raw, 0), d, b); !errors.Is(err, ErrWireLimit) {
		t.Fatal(err)
	}
	under, cancel := context.WithCancel(ctx)
	defer cancel()
	c := &wireCancelContext{Context: under, cancel: cancel}
	if err := ValidateOriginal(c, bytes.Repeat(wireValue(15, 0), 10000), d, b); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel during traversal", err)
	}
	if c.calls.Load() > 65 {
		t.Fatal("continued traversal after cancellation", c.calls.Load())
	}
}

func TestOriginalWireRandomAndConcurrent(t *testing.T) {
	d := wireDescriptor(t)
	b := wireBudget()
	ctx := context.Background()
	r := rand.New(rand.NewSource(281))
	for i := 0; i < 10000; i++ {
		raw := make([]byte, r.Intn(128))
		r.Read(raw)
		if err := ValidateOriginal(ctx, raw, d, b); err == nil {
			if err = ValidateOriginal(ctx, wireJoin(raw, wireValue(25, 0)), d, b); !errors.Is(err, ErrWireInvalid) {
				t.Fatalf("unknown suffix i%d: %v", i, err)
			}
		}
	}
	var wg sync.WaitGroup
	for n := 0; n < 64; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 128; i++ {
				if err := ValidateOriginal(ctx, wireField(15, 2, []byte{0, 1, 2}), d, b); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func FuzzOriginalWire(f *testing.F) {
	d := wireDescriptor(f)
	b := wireBudget()
	b.MaxBytes = 4096
	b.MaxWork = 4096
	b.MaxRepeated = 4096
	for _, raw := range [][]byte{{}, {8, 0}, {8, 0x80}, {0x72, 1, 0xff}, {0x82, 1, 0}, {0x7a, 3, 0, 1, 2}} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		err := ValidateOriginal(context.Background(), raw, d, b)
		if len(raw) > 4096 && !errors.Is(err, ErrWireLimit) {
			t.Fatal("byte bound", err)
		}
	})
}
