package pubsub

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	uadpSecurityHeaderBytes = 14
	uadpSignatureBytes      = 32
)

// UADPSecurityMode is the supported PubSub-Aes256-CTR protection mode.
type UADPSecurityMode uint8

const (
	UADPSecuritySign           UADPSecurityMode = 1
	UADPSecuritySignAndEncrypt UADPSecurityMode = 3
)

// UADPSecurityToken contains key material supplied by a Security Key Service.
// Callers are responsible for protecting and rotating these bytes.
type UADPSecurityToken struct {
	ID            uint32
	SigningKey    []byte
	EncryptingKey []byte
	KeyNonce      []byte
}

func validateUADPSecurity(token UADPSecurityToken, mode UADPSecurityMode) error {
	if mode != UADPSecuritySign && mode != UADPSecuritySignAndEncrypt {
		return errors.New("unsupported UADP security mode")
	}
	if token.ID == 0 || len(token.SigningKey) != 32 || len(token.EncryptingKey) != 32 || len(token.KeyNonce) != 4 {
		return errors.New("invalid PubSub-Aes256-CTR security token")
	}
	return nil
}

// ValidateUADPSecurity validates PubSub-Aes256-CTR key material and mode
// without retaining or modifying the supplied keys.
func ValidateUADPSecurity(token UADPSecurityToken, mode UADPSecurityMode) error {
	return validateUADPSecurity(token, mode)
}

func uadpCTR(token UADPSecurityToken, nonce [8]byte, payload []byte) error {
	block, err := aes.NewCipher(token.EncryptingKey)
	if err != nil {
		return err
	}
	var counter [aes.BlockSize]byte
	copy(counter[:4], token.KeyNonce)
	copy(counter[4:12], nonce[:])
	counter[15] = 1
	cipher.NewCTR(block, counter[:]).XORKeyStream(payload, payload)
	return nil
}
