package pubsub

import (
	"reflect"
	"testing"
)

func TestRawKeyFrameStructureArray(t *testing.T) {
	t.Parallel()
	structure := &RawStructureMeta{Fields: []RawStructureFieldMeta{
		{Name: "count", Field: RawFieldMeta{Type: RawUInt16}},
		{Name: "label", Optional: true, Field: RawFieldMeta{Type: RawString, MaxStringLength: 2}},
	}}
	meta := RawFieldMeta{Type: RawStructureType, Structure: structure, ValueRank: 1, ArrayDimensions: []uint32{2}}
	value := []any{RawStructure{Fields: map[string]any{"count": uint16(7)}}}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: meta.Type, Structure: structure, ValueRank: 1, ArrayDimensions: []uint32{2}, Value: value}}})
	if err != nil {
		t.Fatal(err)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(wire, []RawFieldMeta{meta})
	if err != nil || used != len(wire) || !reflect.DeepEqual(got.Fields[0].Value, value) {
		t.Fatalf("got=%#v used=%d err=%v", got, used, err)
	}
	bad := append([]byte(nil), wire...)
	bad[len(bad)-1] = 1
	if _, _, err := DecodeRawKeyFrameWithMetadata(bad, []RawFieldMeta{meta}); err == nil {
		t.Fatal("nonzero Structure array padding accepted")
	}
}

func TestRawKeyFrameStructureMatrix(t *testing.T) {
	t.Parallel()
	structure := &RawStructureMeta{Fields: []RawStructureFieldMeta{{Name: "enabled", Field: RawFieldMeta{Type: RawBoolean}}}}
	meta := RawFieldMeta{Type: RawStructureType, Structure: structure, ValueRank: 2, ArrayDimensions: []uint32{2, 2}}
	value := RawMatrix{Dimensions: []int32{1, 2}, Values: []any{
		RawStructure{Fields: map[string]any{"enabled": true}},
		RawStructure{Fields: map[string]any{"enabled": false}},
	}}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: meta.Type, Structure: structure, ValueRank: 2, ArrayDimensions: []uint32{2, 2}, Value: value}}})
	if err != nil {
		t.Fatal(err)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(wire, []RawFieldMeta{meta})
	if err != nil || used != len(wire) || !reflect.DeepEqual(got.Fields[0].Value, value) {
		t.Fatalf("got=%#v used=%d err=%v", got, used, err)
	}
}

func TestRawKeyFrameNestedStructureArray(t *testing.T) {
	t.Parallel()
	element := &RawStructureMeta{Fields: []RawStructureFieldMeta{{Name: "value", Field: RawFieldMeta{Type: RawUInt16}}}}
	meta := RawFieldMeta{Type: RawStructureType, Structure: &RawStructureMeta{Fields: []RawStructureFieldMeta{
		{Name: "items", Field: RawFieldMeta{Type: RawStructureType, Structure: element, ValueRank: 1, ArrayDimensions: []uint32{2}}},
	}}}
	value := RawStructure{Fields: map[string]any{"items": []any{RawStructure{Fields: map[string]any{"value": uint16(9)}}}}}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: meta.Type, Structure: meta.Structure, Value: value}}})
	if err != nil {
		t.Fatal(err)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(wire, []RawFieldMeta{meta})
	if err != nil || used != len(wire) || !reflect.DeepEqual(got.Fields[0].Value, value) {
		t.Fatalf("got=%#v used=%d err=%v", got, used, err)
	}
}
