//go:build !go1.27

package x509

import (
	"errors"
	"testing"
)

// Without crypto/mldsa, ML-DSA certificates parse but their signatures are
// reported as unsupported rather than invalid.
func TestMLDSASignaturesUnsupported(t *testing.T) {
	c := parseMLDSATestCertificate(t, "mldsa-65-root.pem")
	if c.PublicKey != nil {
		t.Errorf("PublicKey = %T, want nil", c.PublicKey)
	}
	if c.SelfSigned {
		t.Error("SelfSigned = true, want false")
	}
	if err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("CheckSignature = %v, want ErrUnsupportedAlgorithm", err)
	}
}
