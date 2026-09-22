package pubsub

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestUADPChunkGoldenAndOwnership(t *testing.T) {
	want, _ := hex.DecodeString("d1830108070605040302010a0034120300000005000000aabb")
	input := UADPChunk{PublisherID: 0x0102030405060708, WriterID: 10, MessageSequenceNumber: 0x1234,
		ChunkOffset: 3, TotalSize: 5, Data: []byte{0xaa, 0xbb}}
	wire, err := EncodeUADPChunk(input)
	if err != nil || !bytes.Equal(wire, want) {
		t.Fatalf("wire=%x want=%x err=%v", wire, want, err)
	}
	got, err := DecodeUADPChunk(wire)
	if err != nil || got.PublisherID != input.PublisherID || got.WriterID != 10 || got.MessageSequenceNumber != 0x1234 || got.ChunkOffset != 3 || got.TotalSize != 5 || !bytes.Equal(got.Data, input.Data) {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	wire[len(wire)-1] = 0
	if got.Data[1] != 0xbb {
		t.Fatal("decoded chunk aliases input wire")
	}
}

func TestSplitUADPChunksRoundTrip(t *testing.T) {
	message := []byte{0, 1, 2, 3, 4, 5, 6}
	wires, err := SplitUADPChunks(9, 10, 11, message, 26)
	if err != nil || len(wires) != 3 {
		t.Fatalf("chunks=%d err=%v", len(wires), err)
	}
	var joined []byte
	for index, wire := range wires {
		if len(wire) > 26 {
			t.Fatalf("chunk %d size=%d", index, len(wire))
		}
		chunk, err := DecodeUADPChunk(wire)
		if err != nil || chunk.ChunkOffset != uint32(index*3) || chunk.TotalSize != 7 {
			t.Fatalf("chunk %d=%#v err=%v", index, chunk, err)
		}
		joined = append(joined, chunk.Data...)
	}
	if !bytes.Equal(joined, message) {
		t.Fatalf("joined=%x", joined)
	}
	decoded := make([]UADPChunk, len(wires))
	for index, wire := range wires {
		decoded[index], _ = DecodeUADPChunk(wire)
	}
	decoded[0], decoded[2] = decoded[2], decoded[0]
	reassembled, err := ReassembleUADPChunks(decoded)
	if err != nil || !bytes.Equal(reassembled, message) {
		t.Fatalf("reassembled=%x err=%v", reassembled, err)
	}
}

func TestUADPChunkRejectsInvalid(t *testing.T) {
	valid, _ := hex.DecodeString("d1830108070605040302010a0034120300000005000000aabb")
	for _, wire := range [][]byte{
		valid[:23], append([]byte{0xd1, 0x03, 1}, valid[3:]...),
		func() []byte { b := bytes.Clone(valid); b[11], b[12] = 0, 0; return b }(),
		func() []byte { b := bytes.Clone(valid); b[15] = 4; return b }(),
		func() []byte { b := bytes.Clone(valid); b[19], b[20], b[21], b[22] = 0, 0, 0, 0; return b }(),
	} {
		if _, err := DecodeUADPChunk(wire); err == nil {
			t.Fatalf("accepted %x", wire)
		}
	}
	if _, err := SplitUADPChunks(1, 1, 1, []byte{1}, 23); err == nil {
		t.Fatal("accepted header-only maximum")
	}
	for _, chunks := range [][]UADPChunk{
		{{PublisherID: 1, WriterID: 1, MessageSequenceNumber: 1, TotalSize: 4, ChunkOffset: 0, Data: []byte{1, 2}}},
		{{PublisherID: 1, WriterID: 1, MessageSequenceNumber: 1, TotalSize: 4, ChunkOffset: 0, Data: []byte{1, 2}}, {PublisherID: 1, WriterID: 1, MessageSequenceNumber: 1, TotalSize: 4, ChunkOffset: 3, Data: []byte{4}}},
		{{PublisherID: 1, WriterID: 1, MessageSequenceNumber: 1, TotalSize: 4, ChunkOffset: 0, Data: []byte{1, 2}}, {PublisherID: 2, WriterID: 1, MessageSequenceNumber: 1, TotalSize: 4, ChunkOffset: 2, Data: []byte{3, 4}}},
		{{PublisherID: 1, WriterID: 1, MessageSequenceNumber: 1, TotalSize: 4, ChunkOffset: 0, Data: []byte{1}}, {PublisherID: 1, WriterID: 1, MessageSequenceNumber: 1, TotalSize: 4, ChunkOffset: 1, Data: []byte{2, 3}}, {PublisherID: 1, WriterID: 1, MessageSequenceNumber: 1, TotalSize: 4, ChunkOffset: 3, Data: []byte{4}}},
	} {
		if _, err := ReassembleUADPChunks(chunks); err == nil {
			t.Fatalf("accepted invalid chunk set %#v", chunks)
		}
	}
}

func FuzzUADPChunkDecode(f *testing.F) {
	valid, _ := hex.DecodeString("d1830108070605040302010a0034120300000005000000aabb")
	f.Add(valid)
	f.Add(valid[:23])
	f.Fuzz(func(t *testing.T, wire []byte) {
		chunk, err := DecodeUADPChunk(wire)
		if err != nil {
			return
		}
		reencoded, err := EncodeUADPChunk(chunk)
		if err != nil || !bytes.Equal(reencoded, wire) {
			t.Fatalf("noncanonical wire=%x reencoded=%x err=%v", wire, reencoded, err)
		}
	})
}
