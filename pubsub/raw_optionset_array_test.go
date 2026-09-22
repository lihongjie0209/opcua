package pubsub

import (
	"reflect"
	"testing"
)

func TestRawKeyFrameOptionSetArray(t *testing.T) {
	t.Parallel()
	meta := RawFieldMeta{Type: RawOptionSetType, OptionSetLength: 1, ValueRank: 1, ArrayDimensions: []uint32{2}}
	value := []any{RawOptionSet{Value: []byte{1}, ValidBits: []byte{3}}}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: meta.Type, OptionSetLength: 1, ValueRank: 1, ArrayDimensions: []uint32{2}, Value: value}}})
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
		t.Fatal("nonzero OptionSet array padding accepted")
	}
}

func TestRawKeyFrameOptionSetMatrix(t *testing.T) {
	t.Parallel()
	meta := RawFieldMeta{Type: RawOptionSetType, OptionSetLength: 1, ValueRank: 2, ArrayDimensions: []uint32{2, 2}}
	value := RawMatrix{Dimensions: []int32{1, 2}, Values: []any{
		RawOptionSet{Value: []byte{1}, ValidBits: []byte{3}},
		RawOptionSet{Value: []byte{2}, ValidBits: []byte{3}},
	}}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: meta.Type, OptionSetLength: 1, ValueRank: 2, ArrayDimensions: []uint32{2, 2}, Value: value}}})
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
		t.Fatal("nonzero OptionSet matrix padding accepted")
	}
}

func TestRawKeyFrameStructureOptionSetArray(t *testing.T) {
	t.Parallel()
	meta := RawFieldMeta{Type: RawStructureType, Structure: &RawStructureMeta{Fields: []RawStructureFieldMeta{
		{Name: "options", Field: RawFieldMeta{Type: RawOptionSetType, OptionSetLength: 1, ValueRank: 1, ArrayDimensions: []uint32{2}}},
	}}}
	value := RawStructure{Fields: map[string]any{"options": []any{RawOptionSet{Value: []byte{1}, ValidBits: []byte{3}}}}}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: meta.Type, Structure: meta.Structure, Value: value}}})
	if err != nil {
		t.Fatal(err)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(wire, []RawFieldMeta{meta})
	if err != nil || used != len(wire) || !reflect.DeepEqual(got.Fields[0].Value, value) {
		t.Fatalf("got=%#v used=%d err=%v", got, used, err)
	}
}
