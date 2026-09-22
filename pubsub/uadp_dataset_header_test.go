package pubsub

import (
	"bytes"
	"reflect"
	"testing"
)

func headerPtr[T any](value T) *T { return &value }

func TestUADPDataSetHeaderGoldenRoundTrip(t *testing.T) {
	want := UADPDataSetHeader{
		Type: UADPDataSetKeyFrame, SequenceNumber: headerPtr(uint16(7)),
		Timestamp: headerPtr(uint64(1)), PicoSeconds: headerPtr(uint16(99)),
		Status: headerPtr(uint16(2)), MajorVersion: headerPtr(uint32(3)),
		MinorVersion: headerPtr(uint32(4)),
	}
	wire := []byte{0xf9, 0x30, 7, 0, 1, 0, 0, 0, 0, 0, 0, 0, 99, 0, 2, 0, 3, 0, 0, 0, 4, 0, 0, 0}
	encoded, err := EncodeUADPDataSetHeader(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, wire) {
		t.Fatalf("encoded %x, want %x", encoded, wire)
	}
	got, consumed, err := DecodeUADPDataSetHeader(append(wire, 0xaa))
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(wire) || !reflect.DeepEqual(got, want) {
		t.Fatalf("got (%+v, %d), want (%+v, %d)", got, consumed, want, len(wire))
	}
}

func TestUADPDataSetActionHeaderGoldenRoundTrip(t *testing.T) {
	want := UADPDataSetHeader{Type: UADPDataSetActionRequest, ActionTargetID: 9, RequestID: 10, ActionState: 2}
	wire := []byte{0x81, 5, 9, 0, 10, 0, 2}
	encoded, err := EncodeUADPDataSetHeader(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, wire) {
		t.Fatalf("encoded %x, want %x", encoded, wire)
	}
	got, consumed, err := DecodeUADPDataSetHeader(wire)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(wire) || !reflect.DeepEqual(got, want) {
		t.Fatalf("got (%+v, %d), want (%+v, %d)", got, consumed, want, len(wire))
	}
}

func TestUADPDataSetHeaderRejectsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"empty", nil},
		{"non variant", []byte{0}},
		{"raw data", []byte{3}},
		{"missing flags2", []byte{0x81}},
		{"redundant flags2", []byte{0x81, 0}},
		{"reserved flags2", []byte{0x81, 0x40}},
		{"pico without timestamp", []byte{0x81, 0x20}},
		{"truncated sequence", []byte{0x09, 1}},
		{"truncated action", []byte{0x81, 5, 1, 0}},
		{"invalid action state", []byte{0x81, 6, 1, 0, 2, 0, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := DecodeUADPDataSetHeader(tc.wire); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestEncodeUADPDataSetHeaderRejectsInvalid(t *testing.T) {
	tests := []UADPDataSetHeader{
		{Type: 4},
		{Type: UADPDataSetKeyFrame, PicoSeconds: headerPtr(uint16(1))},
		{Type: UADPDataSetKeyFrame, Timestamp: headerPtr(uint64(1)), PicoSeconds: headerPtr(uint16(10000))},
		{Type: UADPDataSetKeyFrame, ActionTargetID: 1},
		{Type: UADPDataSetActionResponse, ActionState: 3},
	}
	for index, header := range tests {
		if _, err := EncodeUADPDataSetHeader(header); err == nil {
			t.Fatalf("case %d: expected rejection", index)
		}
	}
}

func TestDecodeUADPDataSetHeaderClampsPicoSeconds(t *testing.T) {
	header, consumed, err := DecodeUADPDataSetHeader([]byte{0x81, 0x33, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x27})
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 12 || header.PicoSeconds == nil || *header.PicoSeconds != 9999 {
		t.Fatalf("got %+v consumed %d", header, consumed)
	}
}
