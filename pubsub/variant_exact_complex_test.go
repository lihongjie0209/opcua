package pubsub

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/awcullen/opcua/ua"
)

func TestExactVariantComplexScalarGoldenRoundTrip(t *testing.T) {
	numeric := ua.RawNodeID{Kind: ua.RawNodeIDNumeric, NamespaceIndex: 2, Numeric: 300}
	tests := []struct {
		name  string
		value ua.Variant
		wire  []byte
	}{
		{"node id", numeric, []byte{17, 1, 2, 44, 1}},
		{"null string node id", ua.RawNodeID{Kind: ua.RawNodeIDString, NamespaceIndex: 2, String: ua.NullableString{Null: true}}, []byte{17, 3, 2, 0, 0xff, 0xff, 0xff, 0xff}},
		{"expanded node id", ua.RawExpandedNodeID{NodeID: ua.RawNodeID{Kind: ua.RawNodeIDNumeric, Numeric: 72}, NamespaceURIPresent: true, NamespaceURI: ua.NullableString{Value: "urn:x"}, ServerIndexPresent: true, ServerIndex: 3}, []byte{18, 0xc0, 72, 5, 0, 0, 0, 'u', 'r', 'n', ':', 'x', 3, 0, 0, 0}},
		{"qualified name", ua.RawQualifiedName{NamespaceIndex: 2, Name: ua.NullableString{Value: "water"}}, []byte{20, 2, 0, 5, 0, 0, 0, 'w', 'a', 't', 'e', 'r'}},
		{"null qualified name", ua.RawQualifiedName{NamespaceIndex: 2, Name: ua.NullableString{Null: true}}, []byte{20, 2, 0, 0xff, 0xff, 0xff, 0xff}},
		{"binary extension", ua.RawExtensionObject{RawTypeID: &numeric, Encoding: 1, Body: []byte{0xaa, 0xbb}}, []byte{22, 1, 2, 44, 1, 1, 2, 0, 0, 0, 0xaa, 0xbb}},
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

func TestExactVariantComplexScalarRejectsMalformed(t *testing.T) {
	for _, wire := range [][]byte{
		{17, 6},
		{18, 0x80, 1, 0, 0, 0, 0},
		{20, 0, 0, 0xfe, 0xff, 0xff, 0xff},
		{22, 0, 0, 3},
		{22, 0, 0, 1, 2, 0, 0, 0, 1},
	} {
		if _, _, err := DecodeExactVariantPrefix(wire); err == nil {
			t.Fatalf("expected %x to fail", wire)
		}
	}
}
