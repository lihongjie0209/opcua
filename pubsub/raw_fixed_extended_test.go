package pubsub

import (
	"reflect"
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
	"github.com/google/uuid"
)

func TestRawKeyFrameExtendedFixedTypes(t *testing.T) {
	t.Parallel()
	stamp := time.Date(2026, 9, 23, 8, 30, 0, 123000000, time.UTC)
	id := uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff")
	fields := []RawField{
		{Type: RawDateTime, Value: stamp},
		{Type: RawGUID, Value: id},
		{Type: RawStatusCode, Value: ua.StatusCode(0x81234567)},
		{Type: RawGUID, ValueRank: 1, ArrayDimensions: []uint32{2}, Value: []any{id}},
	}
	meta := []RawFieldMeta{
		{Type: RawDateTime},
		{Type: RawGUID},
		{Type: RawStatusCode},
		{Type: RawGUID, ValueRank: 1, ArrayDimensions: []uint32{2}},
	}
	wire, err := EncodeRawKeyFrame(RawKeyFrame{Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	got, used, err := DecodeRawKeyFrameWithMetadata(wire, meta)
	if err != nil || used != len(wire) {
		t.Fatalf("got=%#v used=%d err=%v", got, used, err)
	}
	for i := range fields {
		if !reflect.DeepEqual(got.Fields[i].Value, fields[i].Value) {
			t.Fatalf("field %d=%#v want=%#v", i, got.Fields[i].Value, fields[i].Value)
		}
	}
}
