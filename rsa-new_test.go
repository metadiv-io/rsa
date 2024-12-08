package rsa_test

import (
	"github.com/metadiv-io/rsa"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("New", func() {
	Context("New4096RSAKey", func() {
		It("creates a new 4096-bit RSA key", func() {
			key := rsa.New4096RSAKey()
			Expect(key).NotTo(BeNil())
			Expect(key.Size()).To(Equal(4096))
		})
	})

	Context("NewRSAKey", func() {
		It("creates a new RSA key with 2048 bits", func() {
			key, err := rsa.NewRSAKey(2048)
			Expect(err).NotTo(HaveOccurred())
			Expect(key).NotTo(BeNil())
			Expect(key.Size()).To(Equal(2048))
		})

		It("creates a new RSA key with 4096 bits", func() {
			key, err := rsa.NewRSAKey(4096)
			Expect(err).NotTo(HaveOccurred())
			Expect(key).NotTo(BeNil())
			Expect(key.Size()).To(Equal(4096))
		})

		DescribeTable("invalid bit sizes",
			func(bits int) {
				key, err := rsa.NewRSAKey(bits)
				Expect(err).To(HaveOccurred())
				Expect(key).To(BeNil())
			},
			Entry("negative bits", -1),
			Entry("zero bits", 0),
			Entry("too few bits", 256),
			Entry("non-multiple of 8", 2049),
		)
	})
})
