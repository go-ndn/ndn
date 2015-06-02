package ndn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

type RSAKey struct {
	Name Name
	*rsa.PrivateKey
}

func (key *RSAKey) Locator() Name {
	return key.Name
}

func (key *RSAKey) Private() crypto.PrivateKey {
	return key.PrivateKey
}

func (key *RSAKey) SignatureType() uint64 {
	return SignatureTypeSHA256WithRSA
}

func (key *RSAKey) Sign(v interface{}) (signature []byte, err error) {
	digest, err := NewSHA256(v)
	if err != nil {
		return
	}
	signature, err = rsa.SignPKCS1v15(rand.Reader, key.PrivateKey, crypto.SHA256, digest)
	return
}

func (key *RSAKey) Verify(v interface{}, signature []byte) (err error) {
	digest, err := NewSHA256(v)
	if err != nil {
		return
	}
	err = rsa.VerifyPKCS1v15(&key.PrivateKey.PublicKey, crypto.SHA256, digest, signature)
	if err != nil {
		err = ErrInvalidSignature
		return
	}
	return
}
