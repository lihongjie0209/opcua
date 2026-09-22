package pubsub

import (
	"bytes"
	"reflect"
	"testing"
)

func TestRawKeyFrameMatrixPerDimensionPadding(t *testing.T) {
	t.Parallel()
	meta := []RawFieldMeta{{Type: RawUInt16, ValueRank: 2, ArrayDimensions: []uint32{2, 3}}}
	value := RawMatrix{Dimensions: []int32{2, 2}, Values: []any{uint16(1), uint16(2), uint16(3), uint16(4)}}
	frame := RawKeyFrame{Fields: []RawField{{Type: RawUInt16, ValueRank: 2, ArrayDimensions: []uint32{2, 3}, Value: value}}}
	want := []byte{0x0b, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0,
		1, 0, 2, 0, 0, 0, 3, 0, 4, 0, 0, 0}
	wire, err := EncodeRawKeyFrame(frame)
	if err != nil || !bytes.Equal(wire, want) {
		t.Fatalf("wire=%x err=%v want=%x", wire, err, want)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(wire, meta)
	if err != nil || used != len(wire) || !reflect.DeepEqual(got.Fields[0].Value, value) {
		t.Fatalf("got=%#v used=%d err=%v", got, used, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"wrong rank", func(b []byte) []byte { b[3] = 3; return b }},
		{"oversized dimension", func(b []byte) []byte { b[11] = 4; return b }},
		{"nonzero inner padding", func(b []byte) []byte { b[19] = 1; return b }},
		{"nonzero final padding", func(b []byte) []byte { b[len(b)-1] = 1; return b }},
		{"truncated", func(b []byte) []byte { return b[:len(b)-1] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := tc.mutate(append([]byte(nil), wire...))
			if _, _, err := DecodeRawKeyFrameWithMetadata(bad, meta); err == nil {
				t.Fatal("invalid matrix accepted")
			}
		})
	}
}

func TestRawKeyFrameMatrixStringsAndEmpty(t *testing.T) {
	t.Parallel()
	meta := []RawFieldMeta{{Type: RawString, ValueRank: 2, ArrayDimensions: []uint32{2, 2}, MaxStringLength: 3}}
	for _, tc := range []struct {
		name   string
		matrix RawMatrix
	}{
		{"one cell", RawMatrix{Dimensions: []int32{1, 1}, Values: []any{"hi"}}},
		{"empty", RawMatrix{Dimensions: []int32{0, 2}, Values: []any{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := RawKeyFrame{Fields: []RawField{{Type: RawString, ValueRank: 2, ArrayDimensions: []uint32{2, 2}, MaxStringLength: 3, Value: tc.matrix}}}
			wire, err := EncodeRawKeyFrame(frame)
			if err != nil {
				t.Fatal(err)
			}
			got, used, err := DecodeRawKeyFrameWithMetadata(wire, meta)
			if err != nil || used != len(wire) || !reflect.DeepEqual(got.Fields[0].Value, tc.matrix) {
				t.Fatalf("got=%#v used=%d err=%v", got, used, err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		matrix RawMatrix
	}{
		{"wrong rank", RawMatrix{Dimensions: []int32{2}, Values: []any{"a", "b"}}},
		{"wrong value count", RawMatrix{Dimensions: []int32{1, 2}, Values: []any{"a"}}},
		{"oversized dimension", RawMatrix{Dimensions: []int32{3, 1}, Values: []any{"a", "b", "c"}}},
		{"negative dimension", RawMatrix{Dimensions: []int32{-1, 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: RawString, ValueRank: 2, ArrayDimensions: []uint32{2, 2}, MaxStringLength: 3, Value: tc.matrix}}}); err == nil {
				t.Fatal("invalid matrix accepted")
			}
		})
	}
}

func TestRawKeyFrameThreeDimensionalMatrix(t *testing.T) {
	t.Parallel()
	meta := RawFieldMeta{Type: RawByte, ValueRank: 3, ArrayDimensions: []uint32{2, 2, 2}}
	value := RawMatrix{Dimensions: []int32{1, 2, 1}, Values: []any{byte(9), byte(10)}}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: meta.Type, ValueRank: meta.ValueRank, ArrayDimensions: meta.ArrayDimensions, Value: value}}})
	want := []byte{0x0b, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 9, 0, 10, 0, 0, 0, 0, 0}
	if err != nil || !bytes.Equal(wire, want) {
		t.Fatalf("wire=%x err=%v want=%x", wire, err, want)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(wire, []RawFieldMeta{meta})
	if err != nil || used != len(wire) || !reflect.DeepEqual(got.Fields[0].Value, value) {
		t.Fatalf("got=%#v used=%d err=%v", got, used, err)
	}
}
