package pubsub

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestUADPDynamicGoldenSingleAndMultiple(t *testing.T) {
	for _, tc := range []struct {
		name string
		sets []UADPDynamicDataSet
		hex  string
	}{
		{"single", []UADPDynamicDataSet{{WriterID: 10, Message: []byte{1, 0xaa, 0xbb}}}, "d1030807060504030201010a0001aabb"},
		{"multiple", []UADPDynamicDataSet{{WriterID: 10, Message: []byte{1, 0xaa, 0xbb}}, {WriterID: 20, Message: []byte{0x81, 0}}}, "d1030807060504030201020a0014000300020001aabb8100"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, _ := hex.DecodeString(tc.hex)
			wire, err := EncodeUADPDynamic(UADPDynamicMessage{PublisherID: 0x0102030405060708, DataSets: tc.sets})
			if err != nil || !bytes.Equal(wire, want) {
				t.Fatalf("wire=%x want=%x err=%v", wire, want, err)
			}
			got, err := DecodeUADPDynamic(wire)
			if err != nil || got.PublisherID != 0x0102030405060708 || len(got.DataSets) != len(tc.sets) {
				t.Fatalf("got=%#v err=%v", got, err)
			}
		})
	}
}

func TestUADPDynamicRejectsMalformedAndOwnsBuffers(t *testing.T) {
	valid, _ := hex.DecodeString("d1030807060504030201020a0014000300020001aabb8100")
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { b[1] |= 0x10; return b },
		func(b []byte) []byte { b[10] = 0; return b },
		func(b []byte) []byte { b[13], b[14] = b[11], b[12]; return b },
		func(b []byte) []byte { b[15], b[16] = 0, 0; return b },
		func(b []byte) []byte { return b[:len(b)-1] },
		func(b []byte) []byte { return append(b, 0xff) },
	} {
		if _, err := DecodeUADPDynamic(mutate(bytes.Clone(valid))); err == nil {
			t.Fatal("malformed wire accepted")
		}
	}
	single, _ := hex.DecodeString("d1030807060504030201010a0001aabb")
	got, err := DecodeUADPDynamic(single)
	if err != nil {
		t.Fatal(err)
	}
	single[len(single)-1] = 0
	if got.DataSets[0].Message[2] != 0xbb {
		t.Fatal("decoded payload aliases wire")
	}
}

func FuzzUADPDynamicDecode(f *testing.F) {
	valid, _ := hex.DecodeString("d1030807060504030201020a0014000300020001aabb8100")
	f.Add(valid)
	f.Add([]byte{0xd1, 3})
	f.Fuzz(func(t *testing.T, wire []byte) {
		decoded, err := DecodeUADPDynamic(wire)
		if err != nil {
			return
		}
		reencoded, err := EncodeUADPDynamic(decoded)
		if err != nil || !bytes.Equal(reencoded, wire) {
			t.Fatalf("noncanonical wire=%x reencoded=%x err=%v", wire, reencoded, err)
		}
	})
}
