package rsa_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRsa(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Rsa Suite")
}
