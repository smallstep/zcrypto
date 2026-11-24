package x509

// Encoded ML-DSA public key sizes, FIPS 204 Table 2. They are declared here
// rather than taken from crypto/mldsa so that ML-DSA certificates parse
// identically on toolchains that predate that package; see mldsa_go127.go and
// mldsa_stub.go.
const (
	mldsa44PublicKeySize = 1312
	mldsa65PublicKeySize = 1952
	mldsa87PublicKeySize = 2592
)
