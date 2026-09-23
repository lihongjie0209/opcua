package pubsub

import (
	"bytes"
	"reflect"
	"testing"
)

func TestTypedUADPDataSetGoldenRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		frame    TypedUADPDataSet
		expected int
		wire     []byte
	}{
		{"key", TypedUADPDataSet{Header: UADPDataSetHeader{Type: UADPDataSetKeyFrame, SequenceNumber: headerPtr(uint16(7))}, Fields: []ExactVariantField{{Index: 0, Value: ExactVariantValue{Type: 1, Value: true}}, {Index: 1, Value: ExactVariantValue{Type: 5, Value: uint16(42)}}}}, 2, []byte{9, 7, 0, 2, 0, 1, 1, 5, 42, 0}},
		{"delta", TypedUADPDataSet{Header: UADPDataSetHeader{Type: UADPDataSetDeltaFrame, SequenceNumber: headerPtr(uint16(8))}, Fields: []ExactVariantField{{Index: 2, Value: ExactVariantValue{Type: 4, Value: int16(-2)}}}}, 3, []byte{0x89, 1, 8, 0, 1, 0, 2, 0, 4, 0xfe, 0xff}},
		{"event", TypedUADPDataSet{Header: UADPDataSetHeader{Type: UADPDataSetEvent}, Fields: []ExactVariantField{{Index: 0, Value: ExactVariantValue{Type: 3, Value: uint8(9)}}}}, 1, []byte{0x81, 2, 1, 0, 3, 9}},
		{"keepalive", TypedUADPDataSet{Header: UADPDataSetHeader{Type: UADPDataSetKeepAlive}}, 1, []byte{0x81, 3}},
		{"heartbeat", TypedUADPDataSet{Header: UADPDataSetHeader{Type: UADPDataSetKeyFrame}, Heartbeat: true}, 1, []byte{1}},
		{"action", TypedUADPDataSet{Header: UADPDataSetHeader{Type: UADPDataSetActionRequest, ActionTargetID: 9, RequestID: 10, ActionState: 2}, Fields: []ExactVariantField{}}, 0, []byte{0x81, 5, 9, 0, 10, 0, 2, 0, 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := EncodeTypedUADPDataSet(tc.frame, tc.expected)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire, tc.wire) {
				t.Fatalf("wire %x want %x", wire, tc.wire)
			}
			got, err := DecodeTypedUADPDataSet(wire, tc.expected)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.frame) {
				t.Fatalf("got %#v want %#v", got, tc.frame)
			}
		})
	}
}

func TestTypedUADPDataSetRejectsInvalidBodies(t *testing.T) {
	for _, tc := range []struct {
		wire     []byte
		expected int
	}{
		{nil, 1},
		{[]byte{1}, 0},
		{[]byte{1, 1, 0, 1, 1}, 2},
		{[]byte{0x81, 1, 2, 0, 0, 0, 1, 1, 0, 0, 1, 0}, 2},
		{[]byte{0x81, 1, 1, 0, 2, 0, 1, 1}, 2},
		{[]byte{0x81, 3, 0}, 1},
		{[]byte{1, 1, 0, 1, 1, 0}, 1},
	} {
		if _, err := DecodeTypedUADPDataSet(tc.wire, tc.expected); err == nil {
			t.Fatalf("accepted %x", tc.wire)
		}
	}
}

func TestEncodeTypedUADPDataSetRejectsInvalidBodies(t *testing.T) {
	tests := []struct {
		frame    TypedUADPDataSet
		expected int
	}{
		{TypedUADPDataSet{Header: UADPDataSetHeader{Type: UADPDataSetKeyFrame}}, 1},
		{TypedUADPDataSet{Header: UADPDataSetHeader{Type: UADPDataSetKeepAlive}, Fields: []ExactVariantField{{Value: ExactVariantValue{Type: 1, Value: true}}}}, 1},
		{TypedUADPDataSet{Header: UADPDataSetHeader{Type: UADPDataSetDeltaFrame}, Fields: []ExactVariantField{{Index: 2, Value: ExactVariantValue{Type: 1, Value: true}}}}, 2},
		{TypedUADPDataSet{Header: UADPDataSetHeader{Type: UADPDataSetEvent}, Fields: []ExactVariantField{{Index: 1, Value: ExactVariantValue{Type: 1, Value: true}}}}, 1},
	}
	for i, tc := range tests {
		if _, err := EncodeTypedUADPDataSet(tc.frame, tc.expected); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}
