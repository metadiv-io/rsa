package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

var (
	// ErrInvalidBitSize is returned when the bit size is invalid
	ErrInvalidBitSize = errors.New("bits must be positive and a multiple of 8")
	// ErrBitSizeTooSmall is returned when the bit size is less than 1024
	ErrBitSizeTooSmall = errors.New("minimum bit size is 1024")
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
// Minimum bit size is 1024 and must be a multiple of 8.
func NewRSAKey(bits int) (*PrivateKey, error) {
	// Validate bit size
	if bits <= 0 || bits%8 != 0 {
		return nil, ErrInvalidBitSize
	}
	if bits < 1024 {
		return nil, ErrBitSizeTooSmall
	}

	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{rsaPrivateKey: privKey}, nil
}
