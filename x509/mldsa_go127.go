//go:build go1.27

package x509

import (
	"crypto/mldsa"
	"encoding/asn1"
	"fmt"
)

// parseMLDSAPublicKey returns the ML-DSA public key encoded in data as a
// *mldsa.PublicKey. The caller has already checked the length of data against
// the parameter set named by oid, so any failure here means ML-DSA itself is
// unavailable, as it is with the FIPS 140-3 Go Cryptographic Module v1.0.0.
// In that case it returns nil: the certificate still parses and reports its
// algorithms, but its signatures cannot be checked.
func parseMLDSAPublicKey(oid asn1.ObjectIdentifier, data []byte) interface{} {
	var params mldsa.Parameters
	switch {
	case oid.Equal(oidKeyMLDSA44):
		params = mldsa.MLDSA44()
	case oid.Equal(oidKeyMLDSA65):
		params = mldsa.MLDSA65()
	case oid.Equal(oidKeyMLDSA87):
		params = mldsa.MLDSA87()
	default:
		return nil
	}
	pub, err := mldsa.NewPublicKey(params, data)
	if err != nil {
		return nil
	}
	return pub
}

// checkMLDSASignature verifies a pure ML-DSA signature, with an empty context
// string, as RFC 9881 requires for X.509.
func checkMLDSASignature(publicKey interface{}, algo SignatureAlgorithm, signed, signature []byte) error {
	pub, ok := publicKey.(*mldsa.PublicKey)
	if !ok {
		return ErrUnsupportedAlgorithm
	}
	var keyAlgo SignatureAlgorithm
	switch pub.Parameters() {
	case mldsa.MLDSA44():
		keyAlgo = MLDSA44
	case mldsa.MLDSA65():
		keyAlgo = MLDSA65
	case mldsa.MLDSA87():
		keyAlgo = MLDSA87
	default:
		return ErrUnsupportedAlgorithm
	}
	if algo != keyAlgo {
		return fmt.Errorf("x509: %s signature does not match %s public key", algo, keyAlgo)
	}
	if err := mldsa.Verify(pub, signed, signature, nil); err != nil {
		return fmt.Errorf("x509: ML-DSA verification failure: %w", err)
	}
	return nil
}
