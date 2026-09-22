package pubsub

import (
	"bytes"
	"math"
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
