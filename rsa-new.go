package rsa

import (
	"crypto/rand"
	"crypto/rsa"
)

// New4096RSAKey creates a new RSA private key with 4096 bits.
// 4096 bits is recommended for long-term security beyond 2030.
func New4096RSAKey() *PrivateKey {
	privateKey, err := NewRSAKey(4096)
	if err != nil {
		panic(err) // not expected to happen
	}
	return privateKey
}

// NewRSAKey creates a new RSA private key with the given number of bits.
func NewRSAKey(bits int) (*PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{rsaPrivateKey: privKey}, nil
}
