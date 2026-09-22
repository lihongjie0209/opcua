package pubsub

import (
	"bytes"
	"math"
	"reflect"
	"testing"

	"github.com/awcullen/opcua/ua"
)

func TestExactVariantPrimitiveGoldenRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		value ua.Variant
		wire  []byte
	}{
		{"null", nil, []byte{0}},
		{"boolean", true, []byte{1, 1}},
		{"sbyte", int8(-2), []byte{2, 0xfe}},
		{"byte", uint8(255), []byte{3, 0xff}},
		{"int16", int16(-2), []byte{4, 0xfe, 0xff}},
		{"uint16", uint16(0x1234), []byte{5, 0x34, 0x12}},
		{"int32", int32(-2), []byte{6, 0xfe, 0xff, 0xff, 0xff}},
		{"uint32", uint32(0x12345678), []byte{7, 0x78, 0x56, 0x34, 0x12}},
		{"int64", int64(-2), []byte{8, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"uint64", uint64(0x12345678), []byte{9, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0}},
		{"float", float32(1.5), []byte{10, 0, 0, 0xc0, 0x3f}},
		{"double", 1.5, []byte{11, 0, 0, 0, 0, 0, 0, 0xf8, 0x3f}},
		{"null string", ua.NullableString{Null: true}, []byte{12, 0xff, 0xff, 0xff, 0xff}},
		{"empty string", ua.NullableString{}, []byte{12, 0, 0, 0, 0}},
		{"datetime", ua.RawDateTime(-2), []byte{13, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"guid", ua.RawGUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, []byte{14, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
		{"null bytes", ua.NullableByteString{Null: true}, []byte{15, 0xff, 0xff, 0xff, 0xff}},
		{"empty bytes", ua.NullableByteString{Value: []byte{}}, []byte{15, 0, 0, 0, 0}},
		{"xml", ua.NullableXMLElement{Value: "<x/>"}, []byte{16, 4, 0, 0, 0, '<', 'x', '/', '>'}},
		{"status", ua.StatusCode(0x12345678), []byte{19, 0x78, 0x56, 0x34, 0x12}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := EncodeExactVariant(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire, tc.wire) {
				t.Fatalf("encoded %x, want %x", wire, tc.wire)
			}
			got, used, err := DecodeExactVariantPrefix(append(wire, 0xaa))
			if err != nil {
				t.Fatal(err)
			}
			if used != len(wire) || !reflect.DeepEqual(got, tc.value) {
				t.Fatalf("got (%#v, %d), want (%#v, %d)", got, used, tc.value, len(wire))
			}
		})
	}
}

func TestExactVariantCanonicalNaN(t *testing.T) {
	for _, value := range []ua.Variant{float32(math.NaN()), math.NaN()} {
		wire, err := EncodeExactVariant(value)
		if err != nil {
			t.Fatal(err)
		}
		switch value.(type) {
		case float32:
			if !bytes.Equal(wire, []byte{10, 0, 0, 0xc0, 0xff}) {
				t.Fatalf("float NaN %x", wire)
			}
		case float64:
			if !bytes.Equal(wire, []byte{11, 0, 0, 0, 0, 0, 0xf8, 0xff}) {
				t.Fatalf("double NaN %x", wire)
			}
		}
	}
}

func TestDecodeExactVariantPrefixRejectsMalformed(t *testing.T) {
	for _, wire := range [][]byte{
		nil,
		{1, 2},
		{12, 0xfe, 0xff, 0xff, 0xff},
		{26, 0, 0, 0, 0},
		{0x40},
	} {
		if _, _, err := DecodeExactVariantPrefix(wire); err == nil {
			t.Fatalf("expected %x to fail", wire)
		}
	}
}

func TestEncodeExactVariantRejectsOversize(t *testing.T) {
	if _, err := EncodeExactVariant(ua.NullableByteString{Value: make([]byte, maxUADPDynamicPayloadBytes)}); err == nil {
		t.Fatal("expected oversize rejection")
	}
}
