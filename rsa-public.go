package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var (
	// ErrInvalidPEM is returned when the PEM string is invalid
	ErrInvalidPEM = errors.New("invalid PEM")
	// ErrNotRSAPublicKey is returned when the key is not an RSA public key
	ErrNotRSAPublicKey = errors.New("not an RSA public key")
)

// NewPublicKeyFromPem creates a new public key from a PEM encoded string.
func NewPublicKeyFromPem(pemStr string) (*PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, ErrInvalidPEM
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, ErrNotRSAPublicKey
	}

	return &PublicKey{
		publicKey: rsaPub,
	}, nil
}

// PublicKey is a public key for RSA encryption.
type PublicKey struct {
	publicKey *rsa.PublicKey
}

// Size returns the size of the public key in bits.
func (k *PublicKey) Size() int {
	return k.publicKey.Size()
}

// Pem returns the PEM encoded public key.
func (k *PublicKey) Pem() string {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(k.publicKey)
	if err != nil {
		panic(err) // not expected to happen
	}
	return string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	))
}
