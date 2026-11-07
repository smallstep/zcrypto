//go:build !go1.27

package x509

import "encoding/asn1"

// parseMLDSAPublicKey returns nil because crypto/mldsa requires Go 1.27. ML-DSA
// certificates still parse and report their algorithms; only signature checks
// are unavailable. Remove this file once the minimum Go version is 1.27.
func parseMLDSAPublicKey(asn1.ObjectIdentifier, []byte) interface{} {
	return nil
}

// checkMLDSASignature reports ML-DSA signatures as unsupported because
// crypto/mldsa requires Go 1.27.
func checkMLDSASignature(interface{}, SignatureAlgorithm, []byte, []byte) error {
	return ErrUnsupportedAlgorithm
}
