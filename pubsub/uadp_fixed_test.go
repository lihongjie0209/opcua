package pubsub

import (
	"bytes"
	"testing"
)

func TestUADPFixedHeaderVectors(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		message   UADPFixedMessage
		wire      []byte
		headerLen int
	}{
		{name: "uint16 publisher", message: UADPFixedMessage{PublisherIDBits: 16, PublisherID: 0x1234, WriterGroupID: 0x5678, GroupVersion: 0x01020304, NetworkMessageNumber: 1, SequenceNumber: 9, Payload: []byte{0xaa, 0xbb}}, wire: []byte{0xb1, 0x01, 0x34, 0x12, 0x0f, 0x78, 0x56, 0x04, 0x03, 0x02, 0x01, 0x01, 0x00, 0x09, 0x00, 0xaa, 0xbb}, headerLen: 15},
		{name: "uint64 publisher", message: UADPFixedMessage{PublisherIDBits: 64, PublisherID: 0x0102030405060708, WriterGroupID: 1, GroupVersion: 2, NetworkMessageNumber: 3, SequenceNumber: 4, Payload: []byte{0x09}}, wire: []byte{0xb1, 0x03, 8, 7, 6, 5, 4, 3, 2, 1, 0x0f, 1, 0, 2, 0, 0, 0, 3, 0, 4, 0, 9}, headerLen: 21},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := EncodeUADPFixed(test.message)
			if err != nil || !bytes.Equal(encoded, test.wire) {
				t.Fatalf("encoded=%x err=%v want=%x", encoded, err, test.wire)
			}
			decoded, headerLen, err := DecodeUADPFixed(test.wire)
			if err != nil || headerLen != test.headerLen || decoded.PublisherIDBits != test.message.PublisherIDBits || decoded.PublisherID != test.message.PublisherID || decoded.WriterGroupID != test.message.WriterGroupID || decoded.GroupVersion != test.message.GroupVersion || decoded.NetworkMessageNumber != test.message.NetworkMessageNumber || decoded.SequenceNumber != test.message.SequenceNumber || !bytes.Equal(decoded.Payload, test.message.Payload) {
				t.Fatalf("decoded=%+v header=%d err=%v", decoded, headerLen, err)
			}
			clear(test.wire)
			if !bytes.Equal(decoded.Payload, test.message.Payload) {
				t.Fatal("decoded payload aliases wire buffer")
			}
		})
	}
}

func TestUADPFixedRejectsMalformedFrames(t *testing.T) {
	t.Parallel()
	valid := []byte{0xb1, 0x01, 0x34, 0x12, 0x0f, 0x78, 0x56, 4, 3, 2, 1, 1, 0, 9, 0, 0xaa}
	for _, test := range []struct {
		name string
		wire []byte
	}{
		{name: "wrong version", wire: append([]byte{0xb2}, valid[1:]...)},
		{name: "payload header enabled", wire: append([]byte{0xf1}, valid[1:]...)},
		{name: "security enabled", wire: append([]byte{valid[0], 0x11}, valid[2:]...)},
		{name: "reserved publisher type", wire: append([]byte{valid[0], 0x05}, valid[2:]...)},
		{name: "reserved group flag", wire: append([]byte{valid[0], valid[1], valid[2], valid[3], 0x1f}, valid[5:]...)},
		{name: "zero message number", wire: append(append([]byte(nil), valid[:11]...), append([]byte{0, 0}, valid[13:]...)...)},
		{name: "empty payload", wire: valid[:15]},
		{name: "oversized", wire: make([]byte, MaxUADPMessageBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := DecodeUADPFixed(test.wire); err == nil {
				t.Fatal("malformed UADP frame accepted")
			}
		})
	}
	for length := range 16 {
		if _, _, err := DecodeUADPFixed(valid[:length]); err == nil {
			t.Fatalf("truncated frame accepted at %d bytes", length)
		}
	}
}

func TestUADPFixedRejectsInvalidEncode(t *testing.T) {
	t.Parallel()
	base := UADPFixedMessage{PublisherIDBits: 16, PublisherID: 1, WriterGroupID: 2, NetworkMessageNumber: 1, Payload: []byte{1}}
	for _, test := range []struct {
		name   string
		change func(*UADPFixedMessage)
	}{
		{name: "unsupported publisher type", change: func(m *UADPFixedMessage) { m.PublisherIDBits = 32 }},
		{name: "publisher overflow", change: func(m *UADPFixedMessage) { m.PublisherID = 65536 }},
		{name: "zero message number", change: func(m *UADPFixedMessage) { m.NetworkMessageNumber = 0 }},
		{name: "empty payload", change: func(m *UADPFixedMessage) { m.Payload = nil }},
		{name: "oversized", change: func(m *UADPFixedMessage) { m.Payload = make([]byte, MaxUADPMessageBytes) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := base
			test.change(&message)
			if _, err := EncodeUADPFixed(message); err == nil {
				t.Fatal("invalid UADP message encoded")
			}
		})
	}
}
