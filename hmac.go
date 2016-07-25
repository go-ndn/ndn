package ndn

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	"github.com/go-ndn/tlv"
)

// HMACKey implements Key.
type HMACKey struct {
	Name
	PrivateKey []byte
}

// Locator returns public key locator.
func (key *HMACKey) Locator() Name {
	return key.Name
}

// Private encodes private key.
func (key *HMACKey) Private() ([]byte, error) {
	return key.PrivateKey, nil
}

// Public encodes public key.
func (key *HMACKey) Public() ([]byte, error) {
	return key.PrivateKey, nil
}

// SignatureType returns signature type generated from the key.
func (key *HMACKey) SignatureType() uint64 {
	return SignatureTypeSHA256WithHMAC
}

// Sign creates signature.
func (key *HMACKey) Sign(v interface{}) ([]byte, error) {
	return tlv.Hash(func() hash.Hash {
		return hmac.New(sha256.New, key.PrivateKey)
	}, v)
}

// Verify checks signature.
func (key *HMACKey) Verify(v interface{}, signature []byte) (err error) {
	expectedMAC, err := key.Sign(v)
	if err != nil {
		return
	}
	if !hmac.Equal(signature, expectedMAC) {
		err = ErrInvalidSignature
		return
	}
	return
}
