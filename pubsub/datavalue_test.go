package pubsub

import (
	"bytes"
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
)

func TestDataValueCodec(t *testing.T) {
	want := ua.DataValue{
		Value:             ua.ByteString(string([]byte{0, 255})),
		StatusCode:        ua.StatusCode(0x80000000),
		SourceTimestamp:   time.Unix(-11644473600, 12300).UTC(),
		SourcePicoseconds: 9999,
		ServerTimestamp:   time.Unix(-11644473600, 45600).UTC(),
		ServerPicoseconds: 1,
	}
	wire, err := EncodeDataValue(want)
	if err != nil {
		t.Fatal(err)
	}
	wantWire := []byte{
		0x3f, 15, 2, 0, 0, 0, 0, 255,
		0, 0, 0, 128,
		123, 0, 0, 0, 0, 0, 0, 0, 0x0f, 0x27,
		200, 1, 0, 0, 0, 0, 0, 0, 1, 0,
	}
	if !bytes.Equal(wire, wantWire) {
		t.Fatalf("wire=%x want=%x", wire, wantWire)
	}
	decoded, used, err := DecodeDataValuePrefix(append(wire, 0xaa))
	if err != nil {
		t.Fatal(err)
	}
	if used != len(wire) || decoded.StatusCode != want.StatusCode ||
		decoded.SourcePicoseconds != want.SourcePicoseconds ||
		decoded.ServerPicoseconds != want.ServerPicoseconds {
		t.Fatalf("decoded=%+v used=%d", decoded, used)
	}
	if got, ok := decoded.Value.(ua.ByteString); !ok || got != want.Value {
		t.Fatalf("value=%T(%v)", decoded.Value, decoded.Value)
	}
}

func TestDecodeDataValuePrefixRejectsMalformed(t *testing.T) {
	for _, wire := range [][]byte{{}, {0x40}, {0x01, 0x3f}, {0x01, ua.VariantTypeUInt64, 1}} {
		if _, _, err := DecodeDataValuePrefix(wire); err == nil {
			t.Fatalf("accepted malformed DataValue %x", wire)
		}
	}
}
