package pubsub

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/awcullen/opcua/ua"
)

func TestExactVariantCollectionGoldenRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		value ExactVariantValue
		wire  []byte
	}{
		{"null array", ExactVariantValue{Type: 0x85, Null: true}, []byte{0x85, 0xff, 0xff, 0xff, 0xff}},
		{"empty array", ExactVariantValue{Type: 0x85, Elements: []ExactVariantValue{}}, []byte{0x85, 0, 0, 0, 0}},
		{"uint16 array", ExactVariantValue{Type: 0x85, Elements: []ExactVariantValue{{Type: 5, Value: uint16(7)}, {Type: 5, Value: uint16(500)}}}, []byte{0x85, 2, 0, 0, 0, 7, 0, 0xf4, 1}},
		{"string array", ExactVariantValue{Type: 0x8c, Elements: []ExactVariantValue{{Type: 12, Value: ua.NullableString{Value: "x"}}, {Type: 12, Value: ua.NullableString{Null: true}}}}, []byte{0x8c, 2, 0, 0, 0, 1, 0, 0, 0, 'x', 0xff, 0xff, 0xff, 0xff}},
		{"matrix", ExactVariantValue{Type: 0xc5, Elements: []ExactVariantValue{{Type: 5, Value: uint16(1)}, {Type: 5, Value: uint16(2)}}, Dimensions: []int32{1, 2}}, []byte{0xc5, 2, 0, 0, 0, 1, 0, 2, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0}},
		{"variant array", ExactVariantValue{Type: 0x98, Elements: []ExactVariantValue{{Type: 0}, {Type: 5, Value: uint16(7)}}}, []byte{0x98, 2, 0, 0, 0, 0, 5, 7, 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := EncodeExactVariantValue(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire, tc.wire) {
				t.Fatalf("wire %x want %x", wire, tc.wire)
			}
			got, consumed, err := DecodeExactVariantValuePrefix(append(wire, 0xaa))
			if err != nil {
				t.Fatal(err)
			}
			if consumed != len(wire) || !reflect.DeepEqual(got, tc.value) {
				t.Fatalf("got (%#v,%d), want (%#v,%d)", got, consumed, tc.value, len(wire))
			}
		})
	}
}

func TestExactVariantCollectionRejectsMalformed(t *testing.T) {
	for _, wire := range [][]byte{
		{0x80, 0, 0, 0, 0},
		{0x85, 0xfe, 0xff, 0xff, 0xff},
		{0x85, 1, 4, 0, 0},
		{0xc5, 0, 0, 0, 0},
		{0xc5, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0},
	} {
		if _, _, err := DecodeExactVariantValuePrefix(wire); err == nil {
			t.Fatalf("accepted %x", wire)
		}
	}
}
