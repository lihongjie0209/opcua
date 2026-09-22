package pubsub

import (
	"bytes"
	"reflect"
	"testing"
)

func TestRawKeyFrameUnion(t *testing.T) {
	t.Parallel()
	meta := RawFieldMeta{Type: RawUnionType, Union: &RawUnionMeta{Fields: []RawUnionFieldMeta{
		{Name: "small", Field: RawFieldMeta{Type: RawUInt16}},
		{Name: "label", Field: RawFieldMeta{Type: RawString, MaxStringLength: 3}},
		{Name: "large", Field: RawFieldMeta{Type: RawUInt64}},
	}}}
	value := RawUnion{SwitchField: 2, Value: "hi"}
	want := []byte{0x0b, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 'h', 'i', 0, 0}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: meta.Type, Union: meta.Union, Value: value}}})
	if err != nil || !bytes.Equal(wire, want) {
		t.Fatalf("wire=%x err=%v want=%x", wire, err, want)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(wire, []RawFieldMeta{meta})
	if err != nil || used != len(wire) || !reflect.DeepEqual(got.Fields[0].Value, value) {
		t.Fatalf("got=%#v used=%d err=%v", got, used, err)
	}
	nullValue := RawUnion{}
	nullWire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: meta.Type, Union: meta.Union, Value: nullValue}}})
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := DecodeRawKeyFrameWithMetadata(nullWire, []RawFieldMeta{meta}); err != nil || !reflect.DeepEqual(got.Fields[0].Value, nullValue) {
		t.Fatalf("null=%#v err=%v", got, err)
	}
	for _, wire := range [][]byte{
		{0x0b, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0x0b, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0},
		{0x0b, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 'h', 'i', 0, 1},
	} {
		if _, _, err := DecodeRawKeyFrameWithMetadata(wire, []RawFieldMeta{meta}); err == nil {
			t.Fatalf("invalid Union accepted: %x", wire)
		}
	}
	for _, value := range []RawUnion{{SwitchField: 0, Value: uint16(1)}, {SwitchField: 1}, {SwitchField: 4, Value: uint16(1)}} {
		if _, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: meta.Type, Union: meta.Union, Value: value}}}); err == nil {
			t.Fatalf("invalid Union value accepted: %#v", value)
		}
	}
}

func TestRawKeyFrameNestedUnion(t *testing.T) {
	t.Parallel()
	union := &RawUnionMeta{Fields: []RawUnionFieldMeta{
		{Name: "count", Field: RawFieldMeta{Type: RawUInt16}},
		{Name: "samples", Field: RawFieldMeta{Type: RawUInt16, ValueRank: 1, ArrayDimensions: []uint32{2}}},
	}}
	meta := RawFieldMeta{Type: RawStructureType, Structure: &RawStructureMeta{Fields: []RawStructureFieldMeta{
		{Name: "kind", Field: RawFieldMeta{Type: RawByte}},
		{Name: "choice", Field: RawFieldMeta{Type: RawUnionType, Union: union}},
	}}}
	value := RawStructure{Fields: map[string]any{
		"kind":   byte(1),
		"choice": RawUnion{SwitchField: 2, Value: []any{uint16(7)}},
	}}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: meta.Type, Structure: meta.Structure, Value: value}}})
	if err != nil {
		t.Fatal(err)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(wire, []RawFieldMeta{meta})
	if err != nil || used != len(wire) || !reflect.DeepEqual(got.Fields[0].Value, value) {
		t.Fatalf("got=%#v used=%d err=%v", got, used, err)
	}
}
