package x509

import (
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/smallstep/zcrypto/x509/pkix"
)

const mldsaTestdataPrefix = testdataPrefix + "mldsa/"

func parseMLDSATestCertificate(t *testing.T, filename string) *Certificate {
	t.Helper()
	b, err := os.ReadFile(mldsaTestdataPrefix + filename)
	if err != nil {
		t.Fatalf("could not open %s: %s", filename, err)
	}
	p, _ := pem.Decode(b)
	if p == nil {
		t.Fatalf("bad pem %s", filename)
	}
	c, err := ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("could not parse %s: %s", filename, err)
	}
	return c
}

// TestParseMLDSACertificates checks that ML-DSA algorithms are identified on
// every toolchain, including those without crypto/mldsa.
func TestParseMLDSACertificates(t *testing.T) {
	tests := []struct {
		filename string
		sigAlgo  SignatureAlgorithm
		sigName  string
		sigOID   string
	}{
		{"mldsa-44-root.pem", MLDSA44, "ML-DSA-44", "2.16.840.1.101.3.4.3.17"},
		{"mldsa-65-root.pem", MLDSA65, "ML-DSA-65", "2.16.840.1.101.3.4.3.18"},
		{"mldsa-87-root.pem", MLDSA87, "ML-DSA-87", "2.16.840.1.101.3.4.3.19"},
		// Issued by the ML-DSA-65 root, but holding an ML-DSA-44 key.
		{"mldsa-44-leaf.pem", MLDSA65, "ML-DSA-65", "2.16.840.1.101.3.4.3.18"},
	}
	for _, test := range tests {
		t.Run(test.filename, func(t *testing.T) {
			c := parseMLDSATestCertificate(t, test.filename)
			if c.SignatureAlgorithm != test.sigAlgo {
				t.Errorf("SignatureAlgorithm = %v, want %v", c.SignatureAlgorithm, test.sigAlgo)
			}
			if got := c.SignatureAlgorithmName(); got != test.sigName {
				t.Errorf("SignatureAlgorithmName() = %q, want %q", got, test.sigName)
			}
			if c.PublicKeyAlgorithm != MLDSA {
				t.Errorf("PublicKeyAlgorithm = %v, want %v", c.PublicKeyAlgorithm, MLDSA)
			}
			if got := c.PublicKeyAlgorithmName(); got != "ML-DSA" {
				t.Errorf("PublicKeyAlgorithmName() = %q, want %q", got, "ML-DSA")
			}

			b, err := json.Marshal(c)
			if err != nil {
				t.Fatalf("json.Marshal: %s", err)
			}
			var out struct {
				SignatureAlgorithm struct {
					Name string `json:"name"`
					OID  string `json:"oid"`
				} `json:"signature_algorithm"`
				SubjectKeyInfo struct {
					KeyAlgorithm struct {
						Name string `json:"name"`
					} `json:"key_algorithm"`
				} `json:"subject_key_info"`
			}
			if err := json.Unmarshal(b, &out); err != nil {
				t.Fatalf("json.Unmarshal: %s", err)
			}
			if out.SignatureAlgorithm.Name != test.sigName || out.SignatureAlgorithm.OID != test.sigOID {
				t.Errorf("JSON signature_algorithm = %+v, want {Name:%s OID:%s}", out.SignatureAlgorithm, test.sigName, test.sigOID)
			}
			if out.SubjectKeyInfo.KeyAlgorithm.Name != "ML-DSA" {
				t.Errorf("JSON subject_key_info.key_algorithm.name = %q, want %q", out.SubjectKeyInfo.KeyAlgorithm.Name, "ML-DSA")
			}
		})
	}
}

func TestParseMLDSAPublicKeyLength(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		size int
	}{
		{"ML-DSA-44", oidKeyMLDSA44, mldsa44PublicKeySize},
		{"ML-DSA-65", oidKeyMLDSA65, mldsa65PublicKeySize},
		{"ML-DSA-87", oidKeyMLDSA87, mldsa87PublicKeySize},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, n := range []int{0, test.size - 1, test.size, test.size + 1} {
				keyData := &publicKeyInfo{
					Algorithm: pkix.AlgorithmIdentifier{Algorithm: test.oid},
					PublicKey: asn1.BitString{Bytes: make([]byte, n), BitLength: 8 * n},
				}
				_, err := parsePublicKey(MLDSA, keyData)
				if wantErr := n != test.size; (err != nil) != wantErr {
					t.Errorf("%d-byte key: err = %v, want error: %t", n, err, wantErr)
				}
			}
		})
	}
}
