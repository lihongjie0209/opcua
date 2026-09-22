package pubsub

import (
	"bytes"
	"reflect"
	"testing"
)

func TestRawKeyFrameOptionSetUsesUABinaryStructureCodec(t *testing.T) {
	t.Parallel()
	value := RawOptionSet{Value: []byte{0x05, 0x80}, ValidBits: []byte{0xff, 0x80}}
	field := RawField{Type: RawOptionSetType, OptionSetLength: 2, Value: value}
	want := []byte{0x0b, 0, 0, 2, 0, 0, 0, 0x05, 0x80, 2, 0, 0, 0, 0xff, 0x80}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{field}})
	if err != nil || !bytes.Equal(wire, want) {
		t.Fatalf("wire=%x err=%v want=%x", wire, err, want)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(wire, []RawFieldMeta{{Type: RawOptionSetType, OptionSetLength: 2}})
	if err != nil || used != len(wire) || !reflect.DeepEqual(got.Fields[0].Value, value) {
		t.Fatalf("got=%#v used=%d err=%v", got, used, err)
	}
}

func TestRawKeyFrameOptionSetRejectsInvalid(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		field RawField
	}{
		{"missing length", RawField{Type: RawOptionSetType, Value: RawOptionSet{Value: []byte{1}, ValidBits: []byte{1}}}},
		{"short value", RawField{Type: RawOptionSetType, OptionSetLength: 2, Value: RawOptionSet{Value: []byte{1}, ValidBits: []byte{1, 2}}}},
		{"short valid bits", RawField{Type: RawOptionSetType, OptionSetLength: 2, Value: RawOptionSet{Value: []byte{1, 2}, ValidBits: []byte{1}}}},
		{"wrong value type", RawField{Type: RawOptionSetType, OptionSetLength: 1, Value: []byte{1}}},
		{"array element mismatch", RawField{Type: RawOptionSetType, OptionSetLength: 2, ValueRank: 1, ArrayDimensions: []uint32{1}, Value: []any{RawOptionSet{Value: []byte{1}, ValidBits: []byte{1}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{tc.field}}); err == nil {
				t.Fatal("invalid OptionSet accepted")
			}
		})
	}
	meta := []RawFieldMeta{{Type: RawOptionSetType, OptionSetLength: 2}}
	valid, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: RawOptionSetType, OptionSetLength: 2, Value: RawOptionSet{Value: []byte{1, 2}, ValidBits: []byte{3, 4}}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"wrong value length", func(b []byte) []byte { b[3] = 1; return b }},
		{"wrong valid bits length", func(b []byte) []byte { b[9] = 1; return b }},
		{"truncated", func(b []byte) []byte { return b[:len(b)-1] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := DecodeRawKeyFrameWithMetadata(tc.mutate(append([]byte(nil), valid...)), meta); err == nil {
				t.Fatal("invalid OptionSet wire accepted")
			}
		})
	}
}
