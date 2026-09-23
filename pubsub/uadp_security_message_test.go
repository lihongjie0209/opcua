package pubsub

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func securityMessageToken() UADPSecurityToken {
	return UADPSecurityToken{
		ID: 7, SigningKey: bytes.Repeat([]byte{0x11}, 32),
		EncryptingKey: bytes.Repeat([]byte{0x22}, 32), KeyNonce: []byte{1, 2, 3, 4},
	}
}

func TestUADPSecureFixedMessageRoundTrip(t *testing.T) {
	plain, err := EncodeUADPFixed(UADPFixedMessage{PublisherIDBits: 16, PublisherID: 9, WriterGroupID: 2, GroupVersion: 3, NetworkMessageNumber: 4, SequenceNumber: 5, Payload: []byte{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	testSecureMessageRoundTrip(t, "fixed", plain, 15, ProtectUADPFixed, UnprotectUADPFixed)
}

func TestUADPSecureDynamicMessageRoundTrip(t *testing.T) {
	plain, err := EncodeUADPDynamic(UADPDynamicMessage{PublisherID: 99, DataSets: []UADPDynamicDataSet{{WriterID: 20, Message: []byte{1, 2}}, {WriterID: 10, Message: []byte{3, 4}}}})
	if err != nil {
		t.Fatal(err)
	}
	testSecureMessageRoundTrip(t, "dynamic", plain, 15, ProtectUADPDynamic, UnprotectUADPDynamic)
}

type protectMessage func([]byte, UADPSecurityToken, [8]byte, UADPSecurityMode) ([]byte, error)
type unprotectMessage func([]byte, UADPSecurityToken, UADPSecurityMode) (UADPSecureMessage, error)

func testSecureMessageRoundTrip(t *testing.T, name string, plain []byte, headerLen int, protect protectMessage, unprotect unprotectMessage) {
	t.Helper()
	token := securityMessageToken()
	nonce := [8]byte{5, 6, 7, 8, 1, 0, 0, 0}
	for _, mode := range []UADPSecurityMode{UADPSecuritySign, UADPSecuritySignAndEncrypt} {
		t.Run(name+string(rune('0'+mode)), func(t *testing.T) {
			wire, err := protect(plain, token, nonce, mode)
			if err != nil {
				t.Fatal(err)
			}
			if len(wire) != len(plain)+14+32 || binary.LittleEndian.Uint32(wire[headerLen+1:]) != token.ID || wire[headerLen+5] != 8 || !bytes.Equal(wire[headerLen+6:headerLen+14], nonce[:]) {
				t.Fatalf("invalid secure header: %x", wire)
			}
			mac := hmac.New(sha256.New, token.SigningKey)
			_, _ = mac.Write(wire[:len(wire)-sha256.Size])
			if !hmac.Equal(mac.Sum(nil), wire[len(wire)-sha256.Size:]) {
				t.Fatal("signature does not cover complete message")
			}
			if mode == UADPSecuritySignAndEncrypt {
				block, _ := aes.NewCipher(token.EncryptingKey)
				counter := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 0, 0, 0, 0, 0, 0, 1}
				var first [16]byte
				block.Encrypt(first[:], counter[:])
				if wire[headerLen+14] != plain[headerLen]^first[0] {
					t.Fatal("AES-CTR counter layout mismatch")
				}
			}
			got, err := unprotect(wire, token, mode)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Plain, plain) || got.TokenID != token.ID || got.MessageNonce != nonce || got.Mode != mode {
				t.Fatalf("decoded = %#v", got)
			}
			clear(wire)
			if !bytes.Equal(got.Plain, plain) {
				t.Fatal("decoded message aliases secure wire")
			}
		})
	}
}

func TestUADPSecureMessagesRejectTamperingAndInvalidKeys(t *testing.T) {
	plain, err := EncodeUADPFixed(UADPFixedMessage{PublisherIDBits: 16, PublisherID: 9, NetworkMessageNumber: 1, Payload: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	token := securityMessageToken()
	nonce := [8]byte{5, 6, 7, 8, 1}
	wire, err := ProtectUADPFixed(plain, token, nonce, UADPSecuritySignAndEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte) []byte{
		func(value []byte) []byte { value[7] ^= 1; return value },
		func(value []byte) []byte { value[29] ^= 1; return value },
		func(value []byte) []byte { value[len(value)-1] ^= 1; return value },
		func(value []byte) []byte { return value[:len(value)-1] },
		func(value []byte) []byte { return append(value, 0) },
	} {
		if _, err := UnprotectUADPFixed(mutate(bytes.Clone(wire)), token, UADPSecuritySignAndEncrypt); err == nil {
			t.Fatal("tampered secure message accepted")
		}
	}
	wrong := securityMessageToken()
	wrong.SigningKey[0]++
	if _, err := UnprotectUADPFixed(wire, wrong, UADPSecuritySignAndEncrypt); err == nil {
		t.Fatal("wrong signing key accepted")
	}
	short := securityMessageToken()
	short.EncryptingKey = short.EncryptingKey[:31]
	if _, err := ProtectUADPFixed(plain, short, nonce, UADPSecuritySignAndEncrypt); err == nil {
		t.Fatal("short encryption key accepted")
	}
	nonce[4] = 0
	if _, err := ProtectUADPFixed(plain, token, nonce, UADPSecuritySign); err == nil {
		t.Fatal("zero security sequence accepted")
	}
}
