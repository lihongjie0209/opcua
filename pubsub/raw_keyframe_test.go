package pubsub

import (
	"bytes"
	"math"
	"reflect"
	"testing"
)

func TestRawKeyFrameScalarVector(t *testing.T) {
	t.Parallel()
	frame := RawKeyFrame{SequenceNumber: 0x1234, Fields: []RawField{
		{Type: RawBoolean, Value: true},
		{Type: RawInt16, Value: int16(-2)},
		{Type: RawUInt32, Value: uint32(0x12345678)},
		{Type: RawFloat, Value: float32(1.5)},
	}}
	want := []byte{0x0b, 0x34, 0x12, 0x01, 0xfe, 0xff, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0xc0, 0x3f}
	wire, err := EncodeRawKeyFrame(frame)
	if err != nil || !bytes.Equal(wire, want) {
		t.Fatalf("EncodeRawKeyFrame() = %x, %v; want %x", wire, err, want)
	}
	got, used, err := DecodeRawKeyFrame(append(wire, 0xaa), []RawType{RawBoolean, RawInt16, RawUInt32, RawFloat})
	if err != nil || used != len(wire) || len(got.Fields) != len(frame.Fields) || got.Fields[1].Value != int16(-2) || got.Fields[3].Value != float32(1.5) {
		t.Fatalf("DecodeRawKeyFrame() = %#v, %d, %v", got, used, err)
	}
}

func TestRawKeyFrameOneDimensionalArray(t *testing.T) {
	t.Parallel()
	frame := RawKeyFrame{SequenceNumber: 1, Fields: []RawField{
		{Type: RawUInt16, ValueRank: 1, ArrayDimensions: []uint32{3}, Value: []any{uint16(0x1234), uint16(0x5678)}},
		{Type: RawBoolean, Value: true},
	}}
	want := []byte{0x0b, 1, 0, 2, 0, 0, 0, 0x34, 0x12, 0x78, 0x56, 0, 0, 1}
	wire, err := EncodeRawKeyFrame(frame)
	if err != nil || !bytes.Equal(wire, want) {
		t.Fatalf("wire=%x err=%v want=%x", wire, err, want)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(append(wire, 0xaa), []RawFieldMeta{
		{Type: RawUInt16, ValueRank: 1, ArrayDimensions: []uint32{3}},
		{Type: RawBoolean},
	})
	if err != nil || used != len(wire) || !reflect.DeepEqual(got.Fields[0].Value, []any{uint16(0x1234), uint16(0x5678)}) || got.Fields[1].Value != true {
		t.Fatalf("frame=%#v used=%d err=%v", got, used, err)
	}
}

func TestRawKeyFrameOneDimensionalArrayRejectsInvalid(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		field RawField
	}{
		{"missing dimensions", RawField{Type: RawByte, ValueRank: 1, Value: []any{byte(1)}}},
		{"oversized value", RawField{Type: RawByte, ValueRank: 1, ArrayDimensions: []uint32{1}, Value: []any{byte(1), byte(2)}}},
		{"wrong element", RawField{Type: RawByte, ValueRank: 1, ArrayDimensions: []uint32{2}, Value: []any{uint16(1)}}},
		{"unsupported string array", RawField{Type: RawString, ValueRank: 1, ArrayDimensions: []uint32{2}, MaxStringLength: 3, Value: []any{"x"}}},
		{"rank mismatch", RawField{Type: RawByte, ValueRank: 2, ArrayDimensions: []uint32{2, 2}, Value: []any{byte(1)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{tc.field}}); err == nil {
				t.Fatal("invalid array accepted")
			}
		})
	}
	metadata := []RawFieldMeta{{Type: RawUInt16, ValueRank: 1, ArrayDimensions: []uint32{3}}}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: RawUInt16, ValueRank: 1, ArrayDimensions: []uint32{3}, Value: []any{uint16(1)}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"oversized count", func(b []byte) []byte { b[3] = 4; return b }},
		{"negative count", func(b []byte) []byte { b[3], b[4], b[5], b[6] = 0xfe, 0xff, 0xff, 0xff; return b }},
		{"nonzero padding", func(b []byte) []byte { b[len(b)-1] = 1; return b }},
		{"truncated padding", func(b []byte) []byte { return b[:len(b)-1] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := tc.mutate(append([]byte(nil), wire...))
			if _, _, err := DecodeRawKeyFrameWithMetadata(candidate, metadata); err == nil {
				t.Fatal("invalid wire accepted")
			}
		})
	}
}

func TestRawKeyFrameOneDimensionalArrayTypes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		typ   RawType
		value any
	}{
		{"boolean", RawBoolean, true},
		{"sbyte", RawSByte, int8(-2)},
		{"byte", RawByte, byte(2)},
		{"int16", RawInt16, int16(-2)},
		{"uint16", RawUInt16, uint16(2)},
		{"int32", RawInt32, int32(-2)},
		{"uint32", RawUInt32, uint32(2)},
		{"int64", RawInt64, int64(-2)},
		{"uint64", RawUInt64, uint64(2)},
		{"float", RawFloat, float32(1.5)},
		{"double", RawDouble, float64(1.5)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			field := RawField{Type: tc.typ, ValueRank: 1, ArrayDimensions: []uint32{2}, Value: []any{tc.value}}
			wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{field}})
			if err != nil {
				t.Fatal(err)
			}
			frame, used, err := DecodeRawKeyFrameWithMetadata(wire, []RawFieldMeta{{Type: tc.typ, ValueRank: 1, ArrayDimensions: []uint32{2}}})
			if err != nil || used != len(wire) || !reflect.DeepEqual(frame.Fields[0].Value, []any{tc.value}) {
				t.Fatalf("frame=%#v used=%d err=%v", frame, used, err)
			}
		})
	}
}

func TestRawKeyFrameRejectsInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		frame RawKeyFrame
	}{
		{"empty", RawKeyFrame{}},
		{"type mismatch", RawKeyFrame{Fields: []RawField{{Type: RawUInt16, Value: int16(1)}}}},
		{"float overflow", RawKeyFrame{Fields: []RawField{{Type: RawFloat, Value: math.MaxFloat64}}}},
		{"unsupported", RawKeyFrame{Fields: []RawField{{Type: RawType(19), Value: uint32(1)}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := EncodeRawKeyFrame(tt.frame); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, _, err := DecodeRawKeyFrame([]byte{0x0b, 0, 0}, []RawType{RawUInt16}); err == nil {
		t.Fatal("expected truncated field error")
	}
}

func TestRawKeyFramePaddedStrings(t *testing.T) {
	t.Parallel()
	frame := RawKeyFrame{SequenceNumber: 1, Fields: []RawField{
		{Type: RawString, Value: "hi", MaxStringLength: 4},
		{Type: RawByteString, Value: []byte{0xab}, MaxStringLength: 3},
	}}
	want := []byte{0x0b, 1, 0, 2, 0, 0, 0, 'h', 'i', 0, 0, 1, 0, 0, 0, 0xab, 0, 0}
	wire, err := EncodeRawKeyFrame(frame)
	if err != nil || !bytes.Equal(wire, want) {
		t.Fatalf("EncodeRawKeyFrame() = %x, %v; want %x", wire, err, want)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(wire, []RawFieldMeta{
		{Type: RawString, MaxStringLength: 4},
		{Type: RawByteString, MaxStringLength: 3},
	})
	if err != nil || used != len(wire) || got.Fields[0].Value != "hi" || !bytes.Equal(got.Fields[1].Value.([]byte), []byte{0xab}) {
		t.Fatalf("DecodeRawKeyFrameWithMetadata() = %#v, %d, %v", got, used, err)
	}
}

func TestRawKeyFramePaddedStringRejectsInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		field RawField
	}{
		{"missing maximum", RawField{Type: RawString, Value: "x"}},
		{"oversized", RawField{Type: RawString, Value: "abc", MaxStringLength: 2}},
		{"wrong type", RawField{Type: RawByteString, Value: "x", MaxStringLength: 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{tt.field}}); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	valid, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: RawString, Value: "a", MaxStringLength: 2}}})
	if err != nil {
		t.Fatal(err)
	}
	valid[len(valid)-1] = 1
	if _, _, err := DecodeRawKeyFrameWithMetadata(valid, []RawFieldMeta{{Type: RawString, MaxStringLength: 2}}); err == nil {
		t.Fatal("nonzero padding accepted")
	}
	if _, _, err := DecodeRawKeyFrameWithMetadata(valid[:len(valid)-1], []RawFieldMeta{{Type: RawString, MaxStringLength: 2}}); err == nil {
		t.Fatal("truncated padding accepted")
	}
	if _, _, err := DecodeRawKeyFrame([]byte{0x0b, 1, 0, 0xff, 0xff, 0xff, 0x7f}, []RawType{RawString}); err == nil {
		t.Fatal("type-only decoder accepted String")
	}
}
