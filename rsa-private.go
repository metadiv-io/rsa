package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var (
	// ErrInvalidPrivateKeyPEM is returned when the PEM string is invalid
	ErrInvalidPrivateKeyPEM = errors.New("failed to parse PEM block")
	// ErrInvalidPrivateKey is returned when the key cannot be parsed as an RSA private key
	ErrInvalidPrivateKey = errors.New("failed to parse private key")
)

// NewPrivateKeyFromPem creates a new private key from a PEM encoded string.
func NewPrivateKeyFromPem(pemStr string) (*PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, ErrInvalidPrivateKeyPEM
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}

	return &PrivateKey{
		rsaPrivateKey: privKey,
	}, nil
}

// PrivateKey is a private key for RSA encryption.
type PrivateKey struct {
	rsaPrivateKey *rsa.PrivateKey
}

// Size returns the size of the private key in bits.
func (k *PrivateKey) Size() int {
	return k.rsaPrivateKey.Size() * 8
}

// Pem returns the PEM encoded private key.
func (k *PrivateKey) Pem() string {
	privKeyPem := string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k.rsaPrivateKey),
		},
	))
	return privKeyPem
}

// PublicKey returns the public key for this private key.
func (k *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{publicKey: &k.rsaPrivateKey.PublicKey}
}
