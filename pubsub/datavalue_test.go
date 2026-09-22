package pubsub

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
)

func TestDataValueCodec(t *testing.T) {
	want := ua.DataValue{
		Value:             ua.ByteString(string([]byte{0, 255})),
		StatusCode:        ua.StatusCode(0x80000000),
		SourceTimestamp:   time.Unix(-11644473600, 12300).UTC(),
		SourcePicoseconds: 9999,
		ServerTimestamp:   time.Unix(-11644473600, 45600).UTC(),
		ServerPicoseconds: 1,
	}
	wire, err := EncodeDataValue(want)
	if err != nil {
		t.Fatal(err)
	}
	wantWire := []byte{
		0x3f, 15, 2, 0, 0, 0, 0, 255,
		0, 0, 0, 128,
		123, 0, 0, 0, 0, 0, 0, 0, 0x0f, 0x27,
		200, 1, 0, 0, 0, 0, 0, 0, 1, 0,
	}
	if !bytes.Equal(wire, wantWire) {
		t.Fatalf("wire=%x want=%x", wire, wantWire)
	}
	decoded, used, err := DecodeDataValuePrefix(append(wire, 0xaa))
	if err != nil {
		t.Fatal(err)
	}
	if used != len(wire) || decoded.StatusCode != want.StatusCode ||
		decoded.SourcePicoseconds != want.SourcePicoseconds ||
		decoded.ServerPicoseconds != want.ServerPicoseconds {
		t.Fatalf("decoded=%+v used=%d", decoded, used)
	}
	if got, ok := decoded.Value.(ua.NullableByteString); !ok || got.Null || !bytes.Equal(got.Value, []byte{0, 255}) {
		t.Fatalf("value=%T(%v)", decoded.Value, decoded.Value)
	}
}

func TestDecodeDataValuePrefixRejectsMalformed(t *testing.T) {
	for _, wire := range [][]byte{{}, {0x40}, {0x01, 0x3f}, {0x01, ua.VariantTypeUInt64, 1},
		{0x01, ua.VariantTypeString, 0xfe, 0xff, 0xff, 0xff}} {
		if _, _, err := DecodeDataValuePrefix(wire); err == nil {
			t.Fatalf("accepted malformed DataValue %x", wire)
		}
	}
}

func TestDataValueCodecPreservesNullableVariants(t *testing.T) {
	tests := []struct {
		name  string
		value ua.Variant
		wire  []byte
	}{
		{name: "null string", value: ua.NullableString{Null: true}, wire: []byte{1, ua.VariantTypeString, 0xff, 0xff, 0xff, 0xff}},
		{name: "empty string", value: ua.NullableString{}, wire: []byte{1, ua.VariantTypeString, 0, 0, 0, 0}},
		{name: "null bytes", value: ua.NullableByteString{Null: true}, wire: []byte{1, ua.VariantTypeByteString, 0xff, 0xff, 0xff, 0xff}},
		{name: "empty bytes", value: ua.NullableByteString{Value: []byte{}}, wire: []byte{1, ua.VariantTypeByteString, 0, 0, 0, 0}},
		{name: "null xml", value: ua.NullableXMLElement{Null: true}, wire: []byte{1, ua.VariantTypeXMLElement, 0xff, 0xff, 0xff, 0xff}},
		{name: "empty xml", value: ua.NullableXMLElement{}, wire: []byte{1, ua.VariantTypeXMLElement, 0, 0, 0, 0}},
		{name: "raw datetime", value: ua.RawDateTime(-1), wire: []byte{1, ua.VariantTypeDateTime, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{name: "raw guid", value: ua.RawGUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			wire: []byte{1, ua.VariantTypeGUID, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := EncodeDataValue(ua.DataValue{Value: tt.value})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire, tt.wire) {
				t.Fatalf("wire=%x want=%x", wire, tt.wire)
			}
			decoded, used, err := DecodeDataValuePrefix(wire)
			if err != nil || used != len(wire) {
				t.Fatalf("used=%d err=%v", used, err)
			}
			if !reflect.DeepEqual(decoded.Value, tt.value) {
				t.Fatalf("value=%#v want=%#v", decoded.Value, tt.value)
			}
		})
	}
}

func TestDataValueCodecPreservesRawExtensionObject(t *testing.T) {
	want := ua.RawExtensionObject{
		TypeID:   ua.NewNodeIDNumeric(2, 42),
		Encoding: 1,
		Body:     []byte{0xaa, 0xbb},
	}
	wire, err := EncodeDataValue(ua.DataValue{Value: want})
	if err != nil {
		t.Fatal(err)
	}
	wantWire := []byte{1, ua.VariantTypeExtensionObject, 1, 2, 42, 0, 1, 2, 0, 0, 0, 0xaa, 0xbb}
	if !bytes.Equal(wire, wantWire) {
		t.Fatalf("wire=%x want=%x", wire, wantWire)
	}
	decoded, used, err := DecodeDataValuePrefix(wire)
	if err != nil || used != len(wire) {
		t.Fatalf("used=%d err=%v", used, err)
	}
	got, ok := decoded.Value.(ua.RawExtensionObject)
	if !ok || got.Encoding != want.Encoding || !bytes.Equal(got.Body, want.Body) || !reflect.DeepEqual(got.TypeID, want.TypeID) {
		t.Fatalf("value=%#v", decoded.Value)
	}
}

func TestExactDataValuePreservesRawFields(t *testing.T) {
	status := uint32(0x80000000)
	source := int64(-1)
	server := int64(0x7fffffffffffffff)
	sourcePico := uint16(10000)
	serverPico := uint16(1)
	want := ExactDataValue{
		ValuePresent: true, Value: ua.RawDateTime(-2), StatusCode: &status,
		SourceTimestamp: &source, SourcePicoseconds: &sourcePico,
		ServerTimestamp: &server, ServerPicoseconds: &serverPico,
	}
	wire, err := EncodeExactDataValue(want)
	if err != nil {
		t.Fatal(err)
	}
	decoded, used, err := DecodeExactDataValuePrefix(append(wire, 0xaa))
	if err != nil || used != len(wire) {
		t.Fatalf("used=%d err=%v", used, err)
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("decoded=%#v want=%#v", decoded, want)
	}
}
