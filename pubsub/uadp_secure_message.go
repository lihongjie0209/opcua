package pubsub

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// UADPSecureMessage is an authenticated and optionally decrypted UADP
// NetworkMessage. Plain is owned by the result and never aliases input.
type UADPSecureMessage struct {
	Plain        []byte
	TokenID      uint32
	MessageNonce [8]byte
	Mode         UADPSecurityMode
}

// ProtectUADPFixed authenticates and optionally encrypts one validated fixed
// UADP NetworkMessage using PubSub-Aes256-CTR.
func ProtectUADPFixed(plain []byte, token UADPSecurityToken, nonce [8]byte, mode UADPSecurityMode) ([]byte, error) {
	message, headerLen, err := DecodeUADPFixed(plain)
	if err != nil || headerLen+len(message.Payload) != len(plain) {
		return nil, errors.New("invalid unsecured fixed UADP message")
	}
	return protectUADPMessage(plain, headerLen, token, nonce, mode)
}

// UnprotectUADPFixed authenticates before decrypting and validating one fixed
// UADP NetworkMessage.
func UnprotectUADPFixed(wire []byte, token UADPSecurityToken, mode UADPSecurityMode) (UADPSecureMessage, error) {
	headerLen, err := fixedSecureHeaderLen(wire)
	if err != nil {
		return UADPSecureMessage{}, err
	}
	message, err := unprotectUADPMessage(wire, headerLen, token, mode)
	if err != nil {
		return UADPSecureMessage{}, err
	}
	decoded, decodedHeaderLen, err := DecodeUADPFixed(message.Plain)
	if err != nil || decodedHeaderLen != headerLen || decodedHeaderLen+len(decoded.Payload) != len(message.Plain) {
		return UADPSecureMessage{}, errors.New("invalid secured fixed UADP payload")
	}
	return message, nil
}

// ProtectUADPDynamic authenticates and optionally encrypts one validated
// dynamic UADP NetworkMessage using PubSub-Aes256-CTR.
func ProtectUADPDynamic(plain []byte, token UADPSecurityToken, nonce [8]byte, mode UADPSecurityMode) ([]byte, error) {
	if _, err := DecodeUADPDynamic(plain); err != nil {
		return nil, errors.New("invalid unsecured dynamic UADP message")
	}
	headerLen, err := dynamicPlainHeaderLen(plain)
	if err != nil {
		return nil, err
	}
	return protectUADPMessage(plain, headerLen, token, nonce, mode)
}

// UnprotectUADPDynamic authenticates before decrypting and validating one
// dynamic UADP NetworkMessage.
func UnprotectUADPDynamic(wire []byte, token UADPSecurityToken, mode UADPSecurityMode) (UADPSecureMessage, error) {
	headerLen, err := dynamicSecureHeaderLen(wire)
	if err != nil {
		return UADPSecureMessage{}, err
	}
	message, err := unprotectUADPMessage(wire, headerLen, token, mode)
	if err != nil {
		return UADPSecureMessage{}, err
	}
	if _, err := DecodeUADPDynamic(message.Plain); err != nil {
		return UADPSecureMessage{}, errors.New("invalid secured dynamic UADP payload")
	}
	return message, nil
}

func protectUADPMessage(plain []byte, headerLen int, token UADPSecurityToken, nonce [8]byte, mode UADPSecurityMode) ([]byte, error) {
	if err := validateUADPSecurity(token, mode); err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint32(nonce[4:]) == 0 {
		return nil, errors.New("UADP security sequence must be nonzero")
	}
	if headerLen < 2 || headerLen >= len(plain) || len(plain) > MaxUADPMessageBytes-uadpSecurityHeaderBytes-uadpSignatureBytes {
		return nil, errors.New("secured UADP message exceeds size limit")
	}
	wire := make([]byte, len(plain)+uadpSecurityHeaderBytes+uadpSignatureBytes)
	copy(wire[:headerLen], plain[:headerLen])
	wire[1] |= 0x10
	wire[headerLen] = byte(mode)
	binary.LittleEndian.PutUint32(wire[headerLen+1:], token.ID)
	wire[headerLen+5] = 8
	copy(wire[headerLen+6:headerLen+14], nonce[:])
	copy(wire[headerLen+14:], plain[headerLen:])
	signatureOffset := len(wire) - uadpSignatureBytes
	if mode == UADPSecuritySignAndEncrypt {
		if err := uadpCTR(token, nonce, wire[headerLen+14:signatureOffset]); err != nil {
			return nil, err
		}
	}
	mac := hmac.New(sha256.New, token.SigningKey)
	_, _ = mac.Write(wire[:signatureOffset])
	copy(wire[signatureOffset:], mac.Sum(nil))
	return wire, nil
}

func unprotectUADPMessage(wire []byte, headerLen int, token UADPSecurityToken, mode UADPSecurityMode) (UADPSecureMessage, error) {
	if err := validateUADPSecurity(token, mode); err != nil {
		return UADPSecureMessage{}, err
	}
	const overhead = uadpSecurityHeaderBytes + uadpSignatureBytes
	if len(wire) > MaxUADPMessageBytes || headerLen < 2 || len(wire) <= headerLen+overhead {
		return UADPSecureMessage{}, errors.New("secured UADP message length is invalid")
	}
	if wire[headerLen] != byte(mode) || binary.LittleEndian.Uint32(wire[headerLen+1:]) != token.ID || wire[headerLen+5] != 8 {
		return UADPSecureMessage{}, errors.New("unsupported UADP security header")
	}
	var nonce [8]byte
	copy(nonce[:], wire[headerLen+6:headerLen+14])
	if binary.LittleEndian.Uint32(nonce[4:]) == 0 {
		return UADPSecureMessage{}, errors.New("UADP security sequence must be nonzero")
	}
	signatureOffset := len(wire) - uadpSignatureBytes
	mac := hmac.New(sha256.New, token.SigningKey)
	_, _ = mac.Write(wire[:signatureOffset])
	if !hmac.Equal(mac.Sum(nil), wire[signatureOffset:]) {
		return UADPSecureMessage{}, errors.New("invalid UADP signature")
	}
	plain := make([]byte, len(wire)-overhead)
	copy(plain[:headerLen], wire[:headerLen])
	plain[1] &^= 0x10
	copy(plain[headerLen:], wire[headerLen+uadpSecurityHeaderBytes:signatureOffset])
	if mode == UADPSecuritySignAndEncrypt {
		if err := uadpCTR(token, nonce, plain[headerLen:]); err != nil {
			clear(plain)
			return UADPSecureMessage{}, err
		}
	}
	return UADPSecureMessage{Plain: plain, TokenID: token.ID, MessageNonce: nonce, Mode: mode}, nil
}

func fixedSecureHeaderLen(wire []byte) (int, error) {
	if len(wire) < 2 || wire[0] != 0xb1 {
		return 0, errors.New("unsupported secured fixed UADP message")
	}
	switch wire[1] {
	case 0x11:
		return 15, nil
	case 0x13:
		return 21, nil
	default:
		return 0, errors.New("unsupported secured fixed UADP flags")
	}
}

func dynamicPlainHeaderLen(wire []byte) (int, error) {
	if len(wire) < 11 || wire[0] != 0xd1 || wire[1] != 0x03 || wire[10] == 0 || wire[10] > 64 {
		return 0, errors.New("unsupported unsecured dynamic UADP message")
	}
	return 11 + 2*int(wire[10]), nil
}

func dynamicSecureHeaderLen(wire []byte) (int, error) {
	if len(wire) < 11 || wire[0] != 0xd1 || wire[1] != 0x13 || wire[10] == 0 || wire[10] > 64 {
		return 0, errors.New("unsupported secured dynamic UADP message")
	}
	return 11 + 2*int(wire[10]), nil
}
