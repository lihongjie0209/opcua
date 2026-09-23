package server

import (
	"crypto/rsa"
	"math/big"
	"testing"
)

func TestUserIdentityCiphertextBlockSizeUsesModulus(t *testing.T) {
	modulus := new(big.Int).Lsh(big.NewInt(1), 2047)
	privateKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: modulus, E: 65537},
		D:         big.NewInt(1),
	}
	if got, want := userIdentityCiphertextBlockSize(privateKey), 256; got != want {
		t.Fatalf("ciphertext block size = %d, want modulus width %d", got, want)
	}
	if exponentBytes := len(privateKey.D.Bytes()); exponentBytes == privateKey.Size() {
		t.Fatal("fixture must have a shorter private exponent representation")
	}
}
