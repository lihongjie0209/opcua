package pubsub

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func secureChunkToken() UADPSecurityToken {
	return UADPSecurityToken{ID: 7, SigningKey: bytes.Repeat([]byte{1}, 32), EncryptingKey: bytes.Repeat([]byte{2}, 32), KeyNonce: []byte{3, 4, 5, 6}}
}

func secureChunkNonce(sequence uint32) [8]byte {
	var nonce [8]byte
	copy(nonce[:4], []byte{7, 8, 9, 10})
	binary.LittleEndian.PutUint32(nonce[4:], sequence)
	return nonce
}

func TestUADPSecureChunkRoundTripAndOwnership(t *testing.T) {
	chunk := UADPChunk{PublisherID: 9, WriterID: 10, MessageSequenceNumber: 11, TotalSize: 4, ChunkOffset: 0, Data: []byte{1, 2, 3}}
	for _, mode := range []UADPSecurityMode{UADPSecuritySign, UADPSecuritySignAndEncrypt} {
		wire, err := EncodeUADPSecureChunk(chunk, secureChunkToken(), secureChunkNonce(1), mode)
		if err != nil {
			t.Fatal(err)
		}
		if wire[0] != 0xd1 || wire[1] != 0x93 || wire[2] != 1 || len(wire) != 72 {
			t.Fatalf("mode=%d wire=%x", mode, wire)
		}
		mac := hmac.New(sha256.New, secureChunkToken().SigningKey)
		_, _ = mac.Write(wire[:len(wire)-sha256.Size])
		if !hmac.Equal(mac.Sum(nil), wire[len(wire)-sha256.Size:]) {
			t.Fatal("signature does not cover complete chunk")
		}
		if mode == UADPSecuritySignAndEncrypt {
			block, err := aes.NewCipher(secureChunkToken().EncryptingKey)
			if err != nil {
				t.Fatal(err)
			}
			counter := [16]byte{3, 4, 5, 6, 7, 8, 9, 10, 1, 0, 0, 0, 0, 0, 0, 1}
			var stream [16]byte
			block.Encrypt(stream[:], counter[:])
			if wire[27] != byte(11)^stream[0] || wire[28] != stream[1] {
				t.Fatal("encrypted chunk does not use the standard counter construction")
			}
		}
		decoded, err := DecodeUADPSecureChunk(wire, secureChunkToken(), mode)
		if err != nil || decoded.TokenID != 7 || decoded.MessageNonce != secureChunkNonce(1) || !bytes.Equal(decoded.Data, chunk.Data) {
			t.Fatalf("mode=%d decoded=%#v err=%v", mode, decoded, err)
		}
		wire[27] ^= 0xff
		if decoded.Data[0] != 1 {
			t.Fatal("decoded secure chunk aliases input")
		}
	}
}

func TestSplitUADPSecureChunksRoundTrip(t *testing.T) {
	message := []byte{0, 1, 2, 3, 4, 5, 6}
	nonces := [][8]byte{secureChunkNonce(1), secureChunkNonce(2), secureChunkNonce(3)}
	wires, err := SplitUADPSecureChunks(9, 10, 11, message, 72, nonces, secureChunkToken(), UADPSecuritySignAndEncrypt)
	if err != nil || len(wires) != 3 {
		t.Fatalf("chunks=%d err=%v", len(wires), err)
	}
	chunks := make([]UADPChunk, len(wires))
	for index, wire := range wires {
		if len(wire) > 72 {
			t.Fatalf("chunk %d size=%d", index, len(wire))
		}
		decoded, err := DecodeUADPSecureChunk(wire, secureChunkToken(), UADPSecuritySignAndEncrypt)
		if err != nil || decoded.MessageNonce != nonces[index] {
			t.Fatalf("chunk %d=%#v err=%v", index, decoded, err)
		}
		chunks[index] = decoded.UADPChunk
	}
	joined, err := ReassembleUADPChunks(chunks)
	if err != nil || !bytes.Equal(joined, message) {
		t.Fatalf("joined=%x err=%v", joined, err)
	}
}

func TestUADPSecureChunkRejectsInvalid(t *testing.T) {
	chunk := UADPChunk{PublisherID: 9, WriterID: 10, MessageSequenceNumber: 11, TotalSize: 3, Data: []byte{1, 2, 3}}
	wire, err := EncodeUADPSecureChunk(chunk, secureChunkToken(), secureChunkNonce(1), UADPSecuritySignAndEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[0] = 0 }, func(b []byte) { b[1] = 0x83 }, func(b []byte) { b[13] = 1 },
		func(b []byte) { b[14]++ }, func(b []byte) { b[18] = 7 }, func(b []byte) { b[27] ^= 1 }, func(b []byte) { b[len(b)-1] ^= 1 },
	} {
		bad := bytes.Clone(wire)
		mutate(bad)
		if _, err := DecodeUADPSecureChunk(bad, secureChunkToken(), UADPSecuritySignAndEncrypt); err == nil {
			t.Fatalf("accepted mutated wire=%x", bad)
		}
	}
	if _, err := DecodeUADPChunk(wire); err == nil {
		t.Fatal("unsecured decoder accepted secured chunk")
	}
	plain, _ := EncodeUADPChunk(chunk)
	if _, err := DecodeUADPSecureChunk(plain, secureChunkToken(), UADPSecuritySignAndEncrypt); err == nil {
		t.Fatal("secure decoder accepted unsecured chunk")
	}
	if _, err := SplitUADPSecureChunks(9, 10, 11, chunk.Data, 69, nil, secureChunkToken(), UADPSecuritySign); err == nil {
		t.Fatal("accepted header-only bound")
	}
	if _, err := SplitUADPSecureChunks(9, 10, 11, chunk.Data, 72, nil, secureChunkToken(), UADPSecuritySign); err == nil {
		t.Fatal("accepted wrong nonce count")
	}
	duplicate := [][8]byte{secureChunkNonce(1), secureChunkNonce(1), secureChunkNonce(2)}
	if _, err := SplitUADPSecureChunks(9, 10, 11, []byte{0, 1, 2, 3, 4, 5, 6}, 72, duplicate, secureChunkToken(), UADPSecuritySign); err == nil {
		t.Fatal("accepted duplicate nonces")
	}
}
