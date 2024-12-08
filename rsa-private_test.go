package rsa_test

import (
	"github.com/metadiv-io/rsa"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Private", func() {
	var validPrivateKey *rsa.PrivateKey

	BeforeEach(func() {
		// Create a fresh key for each test
		validPrivateKey = rsa.New4096RSAKey()
	})

	Context("NewPrivateKeyFromPem", func() {
		It("successfully creates a private key from valid PEM", func() {
			pemStr := validPrivateKey.Pem()
			key, err := rsa.NewPrivateKeyFromPem(pemStr)
			Expect(err).NotTo(HaveOccurred())
			Expect(key).NotTo(BeNil())
			Expect(key.Size()).To(Equal(4096))
		})

		It("returns error for invalid PEM string", func() {
			key, err := rsa.NewPrivateKeyFromPem("invalid pem")
			Expect(err).To(MatchError(rsa.ErrInvalidPrivateKeyPEM))
			Expect(key).To(BeNil())
		})

		It("returns error for invalid private key data", func() {
			// Create an invalid PEM block with wrong data
			invalidPem := `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC7/cj+FxhplOoZZzVhxGBDmxrZZQT6cMQLqUJHLwZcw0pQJW/v
H2Q4EFxQ4S5m/ZLodX2WyYecjExg9m1+pRG7KM9C6+xmTe3Vm54vCX+DT1vN9T0N
ZHgzwX/W0SCkSDT0hVp+8dZrqR+ngz/aA6ydHDhZMo0ZY/ZdIHpwjwIDAQAB
-----END RSA PRIVATE KEY-----`
			key, err := rsa.NewPrivateKeyFromPem(invalidPem)
			Expect(err).To(MatchError(rsa.ErrInvalidPrivateKey))
			Expect(key).To(BeNil())
		})
	})

	Context("Size", func() {
		It("returns correct key size in bits", func() {
			Expect(validPrivateKey.Size()).To(Equal(4096))
		})
	})

	Context("Pem", func() {
		It("returns valid PEM format", func() {
			pemStr := validPrivateKey.Pem()
			Expect(pemStr).To(ContainSubstring("-----BEGIN RSA PRIVATE KEY-----"))
			Expect(pemStr).To(ContainSubstring("-----END RSA PRIVATE KEY-----"))

			// Verify the PEM can be parsed back
			key, err := rsa.NewPrivateKeyFromPem(pemStr)
			Expect(err).NotTo(HaveOccurred())
			Expect(key).NotTo(BeNil())
		})
	})

	Context("PublicKey", func() {
		It("returns corresponding public key", func() {
			publicKey := validPrivateKey.PublicKey()
			Expect(publicKey).NotTo(BeNil())

			// The public key should have the same size as the private key
			pemStr := publicKey.Pem()
			Expect(pemStr).To(ContainSubstring("-----BEGIN RSA PUBLIC KEY-----"))
			Expect(pemStr).To(ContainSubstring("-----END RSA PUBLIC KEY-----"))
		})
	})
})
