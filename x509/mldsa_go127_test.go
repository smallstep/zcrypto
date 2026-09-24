//go:build go1.27

package x509

import (
	"crypto/mldsa"
	stdx509 "crypto/x509"
	"testing"
)

func TestMLDSASignatures(t *testing.T) {
	roots := map[string]mldsa.Parameters{
		"mldsa-44-root.pem": mldsa.MLDSA44(),
		"mldsa-65-root.pem": mldsa.MLDSA65(),
		"mldsa-87-root.pem": mldsa.MLDSA87(),
	}
	for filename, params := range roots {
		t.Run(filename, func(t *testing.T) {
			c := parseMLDSATestCertificate(t, filename)
			pub, ok := c.PublicKey.(*mldsa.PublicKey)
			if !ok {
				t.Fatalf("PublicKey is %T, want *mldsa.PublicKey", c.PublicKey)
			}
			if pub.Parameters() != params {
				t.Errorf("PublicKey parameters = %s, want %s", pub.Parameters(), params)
			}
			if !c.SelfSigned {
				t.Error("SelfSigned = false, want true")
			}
		})
	}

	t.Run("invalid signature", func(t *testing.T) {
		c := parseMLDSATestCertificate(t, "mldsa-65-root-invalid-sig.pem")
		if c.SelfSigned {
			t.Error("SelfSigned = true, want false")
		}
	})

	t.Run("chain", func(t *testing.T) {
		leaf := parseMLDSATestCertificate(t, "mldsa-44-leaf.pem")
		root := parseMLDSATestCertificate(t, "mldsa-65-root.pem")
		if err := leaf.CheckSignatureFrom(root); err != nil {
			t.Errorf("CheckSignatureFrom(ML-DSA-65 root) = %v, want nil", err)
		}
	})

	t.Run("parameter mismatch", func(t *testing.T) {
		// The leaf's ML-DSA-65 signature must not be checked with an
		// ML-DSA-44 key, even one whose certificate is otherwise usable.
		leaf := parseMLDSATestCertificate(t, "mldsa-44-leaf.pem")
		wrong := parseMLDSATestCertificate(t, "mldsa-44-root.pem")
		if err := CheckSignatureFromKey(wrong.PublicKey, leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err == nil {
			t.Error("CheckSignatureFromKey with an ML-DSA-44 key accepted an ML-DSA-65 signature")
		}
	})
}

// TestMLDSAMatchesStandardLibrary checks that zcrypto names ML-DSA algorithms
// the same way crypto/x509 does.
func TestMLDSAMatchesStandardLibrary(t *testing.T) {
	for _, filename := range []string{"mldsa-44-root.pem", "mldsa-65-root.pem", "mldsa-87-root.pem", "mldsa-44-leaf.pem"} {
		t.Run(filename, func(t *testing.T) {
			c := parseMLDSATestCertificate(t, filename)
			std, err := stdx509.ParseCertificate(c.Raw)
			if err != nil {
				t.Fatalf("crypto/x509: %s", err)
			}
			if got, want := c.SignatureAlgorithm.String(), std.SignatureAlgorithm.String(); got != want {
				t.Errorf("SignatureAlgorithm = %q, crypto/x509 has %q", got, want)
			}
			if got, want := c.PublicKeyAlgorithm.String(), std.PublicKeyAlgorithm.String(); got != want {
				t.Errorf("PublicKeyAlgorithm = %q, crypto/x509 has %q", got, want)
			}
		})
	}
}
