package pubsub

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const uadpSecureChunkOverhead = uadpSecurityHeaderBytes + uadpSignatureBytes

// UADPSecureChunk exposes authenticated security metadata with the chunk.
// Replay protection and nonce reservation remain caller responsibilities.
type UADPSecureChunk struct {
	UADPChunk
	TokenID      uint32
	MessageNonce [8]byte
	Mode         UADPSecurityMode
}

// EncodeUADPSecureChunk protects one chunk as an independent NetworkMessage.
func EncodeUADPSecureChunk(chunk UADPChunk, token UADPSecurityToken, nonce [8]byte, mode UADPSecurityMode) ([]byte, error) {
	if err := validateUADPSecurity(token, mode); err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint32(nonce[4:]) == 0 {
		return nil, errors.New("UADP security sequence must be nonzero")
	}
	plain, err := EncodeUADPChunk(chunk)
	if err != nil {
		return nil, err
	}
	const headerBytes = 13
	wire := make([]byte, len(plain)+uadpSecureChunkOverhead)
	copy(wire[:headerBytes], plain[:headerBytes])
	wire[1] |= 0x10
	wire[headerBytes] = byte(mode)
	binary.LittleEndian.PutUint32(wire[headerBytes+1:], token.ID)
	wire[headerBytes+5] = 8
	copy(wire[headerBytes+6:headerBytes+14], nonce[:])
	signatureOffset := len(wire) - uadpSignatureBytes
	copy(wire[headerBytes+uadpSecurityHeaderBytes:signatureOffset], plain[headerBytes:])
	if mode == UADPSecuritySignAndEncrypt {
		if err := uadpCTR(token, nonce, wire[headerBytes+uadpSecurityHeaderBytes:signatureOffset]); err != nil {
			return nil, err
		}
	}
	mac := hmac.New(sha256.New, token.SigningKey)
	_, _ = mac.Write(wire[:signatureOffset])
	copy(wire[signatureOffset:], mac.Sum(nil))
	return wire, nil
}

// DecodeUADPSecureChunk authenticates before decrypting or parsing the payload.
func DecodeUADPSecureChunk(wire []byte, token UADPSecurityToken, mode UADPSecurityMode) (UADPSecureChunk, error) {
	if err := validateUADPSecurity(token, mode); err != nil {
		return UADPSecureChunk{}, err
	}
	const headerBytes = 13
	if len(wire) <= uadpChunkHeaderBytes+uadpSecureChunkOverhead ||
		len(wire) > uadpChunkHeaderBytes+maxUADPDynamicPayloadBytes+uadpSecureChunkOverhead ||
		wire[0] != 0xd1 || wire[1] != 0x93 || wire[2] != 0x01 {
		return UADPSecureChunk{}, errors.New("unsupported secured UADP chunk")
	}
	if wire[headerBytes] != byte(mode) || binary.LittleEndian.Uint32(wire[headerBytes+1:]) != token.ID || wire[headerBytes+5] != 8 {
		return UADPSecureChunk{}, errors.New("unsupported UADP chunk security header")
	}
	var nonce [8]byte
	copy(nonce[:], wire[headerBytes+6:headerBytes+14])
	if binary.LittleEndian.Uint32(nonce[4:]) == 0 {
		return UADPSecureChunk{}, errors.New("UADP security sequence must be nonzero")
	}
	signatureOffset := len(wire) - uadpSignatureBytes
	mac := hmac.New(sha256.New, token.SigningKey)
	_, _ = mac.Write(wire[:signatureOffset])
	if !hmac.Equal(mac.Sum(nil), wire[signatureOffset:]) {
		return UADPSecureChunk{}, errors.New("invalid UADP signature")
	}
	plain := make([]byte, len(wire)-uadpSecureChunkOverhead)
	copy(plain[:headerBytes], wire[:headerBytes])
	plain[1] &^= 0x10
	copy(plain[headerBytes:], wire[headerBytes+uadpSecurityHeaderBytes:signatureOffset])
	if mode == UADPSecuritySignAndEncrypt {
		if err := uadpCTR(token, nonce, plain[headerBytes:]); err != nil {
			return UADPSecureChunk{}, err
		}
	}
	chunk, err := DecodeUADPChunk(plain)
	if err != nil {
		return UADPSecureChunk{}, err
	}
	return UADPSecureChunk{UADPChunk: chunk, TokenID: token.ID, MessageNonce: nonce, Mode: mode}, nil
}

// SplitUADPSecureChunks creates canonical chunks and protects each with its
// corresponding nonce. The nonce count must exactly match the chunk count.
func SplitUADPSecureChunks(publisherID uint64, writerID, sequence uint16, message []byte, maxNetworkMessageBytes int, nonces [][8]byte, token UADPSecurityToken, mode UADPSecurityMode) ([][]byte, error) {
	plainBound := maxNetworkMessageBytes - uadpSecureChunkOverhead
	if plainBound <= uadpChunkHeaderBytes {
		return nil, errors.New("secured UADP chunk network-message bound is invalid")
	}
	plains, err := SplitUADPChunks(publisherID, writerID, sequence, message, plainBound)
	if err != nil {
		return nil, err
	}
	if len(nonces) != len(plains) {
		return nil, errors.New("secured UADP chunk nonce count does not match chunk count")
	}
	seenNonces := make(map[[8]byte]struct{}, len(nonces))
	for _, nonce := range nonces {
		if _, exists := seenNonces[nonce]; exists {
			return nil, errors.New("secured UADP chunk nonces must be distinct")
		}
		seenNonces[nonce] = struct{}{}
	}
	result := make([][]byte, len(plains))
	for index, plain := range plains {
		chunk, err := DecodeUADPChunk(plain)
		if err != nil {
			return nil, err
		}
		result[index], err = EncodeUADPSecureChunk(chunk, token, nonces[index], mode)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
