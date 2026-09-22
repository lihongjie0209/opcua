package pubsub

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestRawKeyFrameNestedStructure(t *testing.T) {
	t.Parallel()
	nested := &RawStructureMeta{Fields: []RawStructureFieldMeta{{Name: "enabled", Field: RawFieldMeta{Type: RawBoolean}}, {Name: "label", Field: RawFieldMeta{Type: RawString, MaxStringLength: 3}}}}
	meta := RawFieldMeta{Type: RawStructureType, Structure: &RawStructureMeta{Fields: []RawStructureFieldMeta{
		{Name: "count", Field: RawFieldMeta{Type: RawUInt16}},
		{Name: "state", Field: RawFieldMeta{Type: RawStructureType, Structure: nested}},
		{Name: "options", Field: RawFieldMeta{Type: RawOptionSetType, OptionSetLength: 1}},
	}}}
	value := RawStructure{Fields: map[string]any{
		"count":   uint16(42),
		"state":   RawStructure{Fields: map[string]any{"enabled": true, "label": "ok"}},
		"options": RawOptionSet{Value: []byte{1}, ValidBits: []byte{3}},
	}}
	field := RawField{Type: meta.Type, Structure: meta.Structure, Value: value}
	if width, err := RawFieldWidth(meta); err != nil || width != 20 {
		t.Fatalf("width=%d err=%v", width, err)
	}
	want := []byte{0x0b, 0, 0, 42, 0, 1, 2, 0, 0, 0, 'o', 'k', 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 3}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{field}})
	if err != nil || !bytes.Equal(wire, want) {
		t.Fatalf("wire=%x err=%v want=%x", wire, err, want)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(wire, []RawFieldMeta{meta})
	if err != nil || used != len(wire) || !reflect.DeepEqual(got.Fields[0].Value, value) {
		t.Fatalf("got=%#v used=%d err=%v", got, used, err)
	}
	badPadding := append([]byte(nil), wire...)
	badPadding[12] = 1
	if _, _, err := DecodeRawKeyFrameWithMetadata(badPadding, []RawFieldMeta{meta}); err == nil {
		t.Fatal("nonzero nested string padding accepted")
	}
}

func TestRawKeyFrameStructureRejectsInvalid(t *testing.T) {
	t.Parallel()
	validMeta := &RawStructureMeta{Fields: []RawStructureFieldMeta{{Name: "value", Field: RawFieldMeta{Type: RawUInt16}}}}
	for _, tc := range []struct {
		name  string
		field RawField
	}{
		{"missing metadata", RawField{Type: RawStructureType, Value: RawStructure{Fields: map[string]any{}}}},
		{"missing value", RawField{Type: RawStructureType, Structure: validMeta, Value: RawStructure{Fields: map[string]any{}}}},
		{"extra value", RawField{Type: RawStructureType, Structure: validMeta, Value: RawStructure{Fields: map[string]any{"value": uint16(1), "extra": true}}}},
		{"wrong field type", RawField{Type: RawStructureType, Structure: validMeta, Value: RawStructure{Fields: map[string]any{"value": int16(1)}}}},
		{"invalid structure array", RawField{Type: RawStructureType, Structure: validMeta, ValueRank: 1, ArrayDimensions: []uint32{0}, Value: []any{}}},
		{"duplicate names", RawField{Type: RawStructureType, Structure: &RawStructureMeta{Fields: []RawStructureFieldMeta{{Name: "x", Field: RawFieldMeta{Type: RawByte}}, {Name: "x", Field: RawFieldMeta{Type: RawByte}}}}, Value: RawStructure{Fields: map[string]any{"x": byte(1)}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{tc.field}}); err == nil {
				t.Fatal("invalid Structure accepted")
			}
		})
	}
	deep := RawFieldMeta{Type: RawUInt16}
	for range 17 {
		deep = RawFieldMeta{Type: RawStructureType, Structure: &RawStructureMeta{Fields: []RawStructureFieldMeta{{Name: "x", Field: deep}}}}
	}
	if _, _, err := DecodeRawKeyFrameWithMetadata(make([]byte, 128), []RawFieldMeta{deep}); err == nil {
		t.Fatal("over-depth Structure accepted")
	}
	if _, _, err := DecodeRawKeyFrameWithMetadata([]byte{0x0b, 0, 0, 1}, []RawFieldMeta{{Type: RawStructureType, Structure: validMeta}}); err == nil {
		t.Fatal("truncated Structure accepted")
	}
}

func TestRawKeyFrameStructureArraysAndMatrix(t *testing.T) {
	t.Parallel()
	meta := RawFieldMeta{Type: RawStructureType, Structure: &RawStructureMeta{Fields: []RawStructureFieldMeta{
		{Name: "samples", Field: RawFieldMeta{Type: RawUInt16, ValueRank: 1, ArrayDimensions: []uint32{3}}},
		{Name: "labels", Field: RawFieldMeta{Type: RawString, ValueRank: 2, ArrayDimensions: []uint32{2, 2}, MaxStringLength: 2}},
	}}}
	value := RawStructure{Fields: map[string]any{
		"samples": []any{uint16(1), uint16(2)},
		"labels":  RawMatrix{Dimensions: []int32{1, 2}, Values: []any{"a", "b"}},
	}}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: RawStructureType, Structure: meta.Structure, Value: value}}})
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
		t.Fatal("nonzero nested matrix padding accepted")
	}
}

func TestRawKeyFrameOptionalStructureFields(t *testing.T) {
	t.Parallel()
	meta := RawFieldMeta{Type: RawStructureType, Structure: &RawStructureMeta{Fields: []RawStructureFieldMeta{
		{Name: "count", Field: RawFieldMeta{Type: RawUInt16}},
		{Name: "label", Optional: true, Field: RawFieldMeta{Type: RawString, MaxStringLength: 2}},
		{Name: "enabled", Field: RawFieldMeta{Type: RawBoolean}},
		{Name: "samples", Optional: true, Field: RawFieldMeta{Type: RawUInt16, ValueRank: 1, ArrayDimensions: []uint32{2}}},
	}}}
	value := RawStructure{Fields: map[string]any{"count": uint16(42), "enabled": true, "samples": []any{uint16(9)}}}
	want := []byte{0x0b, 0, 0, 2, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 9, 0, 0, 0}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: RawStructureType, Structure: meta.Structure, Value: value}}})
	if err != nil || !bytes.Equal(wire, want) {
		t.Fatalf("wire=%x err=%v want=%x", wire, err, want)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(wire, []RawFieldMeta{meta})
	if err != nil || used != len(wire) || !reflect.DeepEqual(got.Fields[0].Value, value) {
		t.Fatalf("got=%#v used=%d err=%v", got, used, err)
	}
	for _, tc := range []struct {
		name  string
		index int
		value byte
	}{{"unassigned mask bit", 3, 4}, {"nonzero absent padding", 9, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			bad := append([]byte(nil), wire...)
			bad[tc.index] = tc.value
			if _, _, err := DecodeRawKeyFrameWithMetadata(bad, []RawFieldMeta{meta}); err == nil {
				t.Fatal("invalid optional Structure accepted")
			}
		})
	}
	if _, err := EncodeRawKeyFrame(RawKeyFrame{Fields: []RawField{{Type: RawStructureType, Structure: meta.Structure, Value: RawStructure{Fields: map[string]any{"enabled": true}}}}}); err == nil {
		t.Fatal("missing mandatory field accepted")
	}
	fields := make([]RawStructureFieldMeta, 33)
	for i := range fields {
		fields[i] = RawStructureFieldMeta{Name: fmt.Sprintf("f%d", i), Optional: true, Field: RawFieldMeta{Type: RawByte}}
	}
	if _, err := RawFieldWidth(RawFieldMeta{Type: RawStructureType, Structure: &RawStructureMeta{Fields: fields}}); err == nil {
		t.Fatal("more than 32 optional fields accepted")
	}
}
