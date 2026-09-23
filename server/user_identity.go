package server

import "crypto/rsa"

// userIdentityCiphertextBlockSize returns the encoded RSA block width. RSA
// ciphertext is always the modulus width; the private exponent may contain
// fewer leading bytes and must not be used to size the block.
func userIdentityCiphertextBlockSize(privateKey *rsa.PrivateKey) int {
	return privateKey.Size()
}
