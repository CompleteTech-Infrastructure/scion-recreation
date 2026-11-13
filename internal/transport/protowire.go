// Package transport contains bounded transport validation building blocks.
package transport

import (
	"context"
	"errors"
	"reflect"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var (
	ErrWireInvalid = errors.New("invalid protobuf wire")
	ErrWireLimit   = errors.New("protobuf wire resource exhausted")
)

// WireBudget is trusted method configuration, never a request's claimed work
// or depth. MaxWork counts every tag and every packed scalar. MaxRepeated is
// per field in each message; an empty packed occurrence still costs one.
type WireBudget struct {
	MaxBytes, MaxWork, MaxRepeated uint64
	MaxDepth                       int
}

// ValidateOriginal checks original companion request bytes BEFORE Unmarshal can
// erase duplicate fields/oneof arms. The method adapter must select a trusted
// descriptor, acquire authenticated admission and bound ingress before reading
// raw. This helper installs no codec, authenticates nobody and checks no domain
// requiredness, grants or policy. Descriptors and raw must not mutate during use.
//
// Root depth is one; every embedded message, even empty, adds one. Workflow
// ceilings are 2MiB, depth16 and 1Mi work/repeated items. Bytes remain opaque;
// strings require UTF-8. Legal packed/unpacked scalar variants are accepted:
// this is strict structural validation, NOT a canonical protobuf signing format.
func ValidateOriginal(ctx context.Context, raw []byte, desc protoreflect.MessageDescriptor, budget WireBudget) error {
	if ctx == nil {
		return ErrWireInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if nilDescriptor(desc) || budget.MaxBytes == 0 || budget.MaxBytes > 2<<20 ||
		budget.MaxDepth < 1 || budget.MaxDepth > 16 || budget.MaxWork == 0 || budget.MaxWork > 1<<20 ||
		budget.MaxRepeated == 0 || budget.MaxRepeated > 1<<20 {
		return ErrWireInvalid
	}
	if uint64(len(raw)) > budget.MaxBytes {
		return ErrWireLimit
	}
	v := wireValidator{ctx: ctx, budget: budget}
	if err := v.message(raw, desc, 1); err != nil {
		return err
	}
	return ctx.Err()
}

func nilDescriptor(d protoreflect.MessageDescriptor) bool {
	if d == nil {
		return true
	}
	r := reflect.ValueOf(d)
	return r.Kind() == reflect.Pointer && r.IsNil()
}

type wireValidator struct {
	ctx    context.Context
	budget WireBudget
	work   uint64
}

func (v *wireValidator) charge() error {
	if err := v.ctx.Err(); err != nil {
		return err
	}
	if v.work == v.budget.MaxWork {
		return ErrWireLimit
	}
	v.work++
	return nil
}

func wireVarint(b []byte) (uint64, int, error) {
	n, size := protowire.ConsumeVarint(b)
	if size < 0 || size != protowire.SizeVarint(n) {
		return 0, 0, ErrWireInvalid
	}
	return n, size, nil
}

func wireBytes(b []byte) ([]byte, int, error) {
	n, size, err := wireVarint(b)
	if err != nil || n > uint64(len(b)-size) {
		return nil, 0, ErrWireInvalid
	}
	return b[size : size+int(n)], size + int(n), nil
}

func (v *wireValidator) message(b []byte, d protoreflect.MessageDescriptor, depth int) error {
	if depth > v.budget.MaxDepth {
		return ErrWireLimit
	}
	if nilDescriptor(d) || d.Fields().Len() > 4096 || d.Oneofs().Len() > 4096 {
		return ErrWireInvalid
	}
	// State is bounded by trusted descriptor sizes, not attacker-supplied counts.
	seen := make([]uint64, d.Fields().Len())
	arms := make([]protoreflect.FieldNumber, d.Oneofs().Len())
	for len(b) != 0 {
		if err := v.charge(); err != nil {
			return err
		}
		tag, size, err := wireVarint(b)
		if err != nil || tag>>3 == 0 || tag>>3 > (1<<29)-1 {
			return ErrWireInvalid
		}
		b = b[size:]
		f := d.Fields().ByNumber(protoreflect.FieldNumber(tag >> 3))
		if f == nil || f.Kind() == protoreflect.GroupKind {
			return ErrWireInvalid
		}
		if f.Cardinality() != protoreflect.Repeated && seen[f.Index()] != 0 {
			return ErrWireInvalid
		}
		if f.Cardinality() == protoreflect.Repeated && seen[f.Index()] == v.budget.MaxRepeated {
			return ErrWireLimit
		}
		if o := f.ContainingOneof(); o != nil {
			if arms[o.Index()] != 0 {
				return ErrWireInvalid
			}
			arms[o.Index()] = f.Number()
		}
		count := uint64(1)
		wire := protowire.Type(tag & 7)
		if wire == protowire.BytesType && f.Cardinality() == protoreflect.Repeated && packable(f.Kind()) {
			packed, n, err := wireBytes(b)
			if err != nil {
				return err
			}
			b = b[n:]
			count = 0
			for len(packed) != 0 {
				if err = v.charge(); err != nil {
					return err
				}
				count++
				if count > v.budget.MaxRepeated-seen[f.Index()] {
					return ErrWireLimit
				}
				n, err = scalar(packed, f, scalarWire(f.Kind()))
				if err != nil {
					return err
				}
				packed = packed[n:]
			}
			if count == 0 {
				count = 1
			}
		} else if wire == protowire.BytesType && (f.Kind() == protoreflect.MessageKind || f.Kind() == protoreflect.BytesKind || f.Kind() == protoreflect.StringKind) {
			value, n, err := wireBytes(b)
			if err != nil {
				return err
			}
			b = b[n:]
			if f.Kind() == protoreflect.MessageKind {
				if err = v.message(value, f.Message(), depth+1); err != nil {
					return err
				}
			} else if f.Kind() == protoreflect.StringKind && !utf8.Valid(value) {
				return ErrWireInvalid
			}
		} else {
			n, err := scalar(b, f, wire)
			if err != nil {
				return err
			}
			b = b[n:]
		}
		if f.Cardinality() == protoreflect.Repeated && count > v.budget.MaxRepeated-seen[f.Index()] {
			return ErrWireLimit
		}
		seen[f.Index()] += count
	}
	return v.ctx.Err()
}

func packable(k protoreflect.Kind) bool {
	switch k {
	case protoreflect.BoolKind, protoreflect.EnumKind, protoreflect.Int32Kind, protoreflect.Int64Kind, protoreflect.Sint32Kind, protoreflect.Sint64Kind, protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.Sfixed32Kind, protoreflect.Fixed32Kind, protoreflect.FloatKind, protoreflect.Sfixed64Kind, protoreflect.Fixed64Kind, protoreflect.DoubleKind:
		return true
	}
	return false
}

func scalarWire(k protoreflect.Kind) protowire.Type {
	switch k {
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return protowire.Fixed32Type
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return protowire.Fixed64Type
	default:
		return protowire.VarintType
	}
}

func scalar(b []byte, f protoreflect.FieldDescriptor, wire protowire.Type) (int, error) {
	if !packable(f.Kind()) || wire != scalarWire(f.Kind()) {
		return 0, ErrWireInvalid
	}
	switch wire {
	case protowire.Fixed32Type:
		if len(b) >= 4 {
			return 4, nil
		}
	case protowire.Fixed64Type:
		if len(b) >= 8 {
			return 8, nil
		}
	case protowire.VarintType:
		n, size, err := wireVarint(b)
		if err != nil {
			return 0, err
		}
		switch f.Kind() {
		case protoreflect.BoolKind:
			if n > 1 {
				return 0, ErrWireInvalid
			}
		case protoreflect.Uint32Kind, protoreflect.Sint32Kind:
			if n > (1<<32)-1 {
				return 0, ErrWireInvalid
			}
		case protoreflect.Int32Kind, protoreflect.EnumKind:
			if n > (1<<31)-1 && n < 0xffffffff80000000 {
				return 0, ErrWireInvalid
			}
			if f.Kind() == protoreflect.EnumKind && f.Enum().Values().ByNumber(protoreflect.EnumNumber(int32(n))) == nil {
				return 0, ErrWireInvalid
			}
		}
		return size, nil
	}
	return 0, ErrWireInvalid
}
