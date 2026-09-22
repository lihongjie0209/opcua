package pubsub

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/awcullen/opcua/ua"
)

func diagnosticPtr[T any](value T) *T { return &value }

func TestExactDiagnosticInfoGoldenRoundTrip(t *testing.T) {
	status := ua.StatusCode(0x80000000)
	want := ua.DiagnosticInfo{
		SymbolicID: diagnosticPtr(int32(1)), NamespaceURI: diagnosticPtr(int32(2)),
		Locale: diagnosticPtr(int32(3)), LocalizedText: diagnosticPtr(int32(4)),
		AdditionalInfo: diagnosticPtr("x"), InnerStatusCode: &status,
		InnerDiagnosticInfo: &ua.DiagnosticInfo{},
	}
	wire := []byte{0x7f, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 'x', 0, 0, 0, 128, 0}
	encoded, err := EncodeExactDiagnosticInfo(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, wire) {
		t.Fatalf("encoded %x, want %x", encoded, wire)
	}
	got, consumed, err := DecodeExactDiagnosticInfoPrefix(append(wire, 0xaa))
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(wire) || !reflect.DeepEqual(got, want) {
		t.Fatalf("got (%+v, %d), want (%+v, %d)", got, consumed, want, len(wire))
	}
}

func TestExactDiagnosticInfoCanonicalizesAbsentValues(t *testing.T) {
	wire := []byte{0x31, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}
	got, consumed, err := DecodeExactDiagnosticInfoPrefix(wire)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(wire) || !reflect.DeepEqual(got, ua.DiagnosticInfo{}) {
		t.Fatalf("got %+v consumed %d", got, consumed)
	}
}

func TestExactDiagnosticInfoRejectsMalformed(t *testing.T) {
	for _, wire := range [][]byte{
		nil,
		{0x80},
		{1, 1},
		{0x10, 0xfe, 0xff, 0xff, 0xff},
		{0x10, 1, 0, 0, 0, 0xff},
	} {
		if _, _, err := DecodeExactDiagnosticInfoPrefix(wire); err == nil {
			t.Fatalf("expected %x to fail", wire)
		}
	}
	deep := []byte{}
	for range 10 {
		deep = append(deep, 0x40)
	}
	deep = append(deep, 0)
	if _, _, err := DecodeExactDiagnosticInfoPrefix(deep); err == nil {
		t.Fatal("accepted depth 11")
	}
}

func TestExactDiagnosticInfoRejectsCycle(t *testing.T) {
	value := ua.DiagnosticInfo{}
	value.InnerDiagnosticInfo = &value
	if _, err := EncodeExactDiagnosticInfo(value); err == nil {
		t.Fatal("accepted cycle")
	}
}
