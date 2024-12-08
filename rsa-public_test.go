package rsa_test

import (
	"github.com/metadiv-io/rsa"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Public", func() {
	var (
		validPrivateKey *rsa.PrivateKey
		validPublicKey  *rsa.PublicKey
	)

	BeforeEach(func() {
		// Create fresh keys for each test
		validPrivateKey = rsa.New4096RSAKey()
		validPublicKey = validPrivateKey.PublicKey()
	})

	Context("NewPublicKeyFromPem", func() {
		It("successfully creates a public key from valid PEM", func() {
			pemStr := validPublicKey.Pem()
			key, err := rsa.NewPublicKeyFromPem(pemStr)
			Expect(err).NotTo(HaveOccurred())
			Expect(key).NotTo(BeNil())
			Expect(key.Size() * 8).To(Equal(4096)) // Size() returns bytes, multiply by 8 for bits
		})

		It("returns error for invalid PEM string", func() {
			key, err := rsa.NewPublicKeyFromPem("invalid pem")
			Expect(err).To(MatchError(rsa.ErrInvalidPEM))
			Expect(key).To(BeNil())
		})

		It("returns error for invalid public key data", func() {
			// Create an invalid PEM block with wrong data
			invalidPem := `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END RSA PUBLIC KEY-----`
			key, err := rsa.NewPublicKeyFromPem(invalidPem)
			Expect(err).To(HaveOccurred()) // Will return x509 parsing error
			Expect(key).To(BeNil())
		})

		It("returns error for non-RSA public key", func() {
			// This is an EC public key PEM (example)
			ecPem := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----`
			key, err := rsa.NewPublicKeyFromPem(ecPem)
			Expect(err).To(MatchError(rsa.ErrNotRSAPublicKey))
			Expect(key).To(BeNil())
		})
	})

	Context("Size", func() {
		It("returns correct key size in bytes", func() {
			// Size returns bytes, so 4096 bits = 512 bytes
			Expect(validPublicKey.Size()).To(Equal(512))
		})
	})

	Context("Pem", func() {
		It("returns valid PEM format", func() {
			pemStr := validPublicKey.Pem()
			Expect(pemStr).To(ContainSubstring("-----BEGIN RSA PUBLIC KEY-----"))
			Expect(pemStr).To(ContainSubstring("-----END RSA PUBLIC KEY-----"))

			// Verify the PEM can be parsed back
			key, err := rsa.NewPublicKeyFromPem(pemStr)
			Expect(err).NotTo(HaveOccurred())
			Expect(key).NotTo(BeNil())
		})

		It("maintains consistency when encoding and decoding", func() {
			originalPem := validPublicKey.Pem()
			key, err := rsa.NewPublicKeyFromPem(originalPem)
			Expect(err).NotTo(HaveOccurred())

			newPem := key.Pem()
			Expect(newPem).To(Equal(originalPem))
		})
	})
})
