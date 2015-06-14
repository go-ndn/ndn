package ndn

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	"github.com/go-ndn/tlv"
)

type HMACKey struct {
	Name       Name
	PrivateKey []byte
}

func (key *HMACKey) Locator() Name {
	return key.Name
}

func (key *HMACKey) Private() crypto.PrivateKey {
	return key
}

func (key *HMACKey) Public() crypto.PublicKey {
	return nil
}

func (key *HMACKey) SignatureType() uint64 {
	return SignatureTypeSHA256WithHMAC
}

func (key *HMACKey) Sign(v interface{}) ([]byte, error) {
	return tlv.Hash(func() hash.Hash {
		return hmac.New(sha256.New, key.PrivateKey)
	}, v)
}

func (key *HMACKey) Verify(v interface{}, signature []byte) (err error) {
	expectedMAC, err := key.Sign(v)
	if err != nil {
		return
	}
	if !bytes.Equal(signature, expectedMAC) {
		err = ErrInvalidSignature
		return
	}
	return
}
