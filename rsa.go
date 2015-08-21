package ndn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	"github.com/go-ndn/tlv"
)

type RSAKey struct {
	Name
	*rsa.PrivateKey
}

func (key *RSAKey) Locator() Name {
	return key.Name
}

func (key *RSAKey) Private() ([]byte, error) {
	return x509.MarshalPKCS1PrivateKey(key.PrivateKey), nil
}

func (key *RSAKey) Public() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key.PrivateKey.Public())
}

func (key *RSAKey) SignatureType() uint64 {
	return SignatureTypeSHA256WithRSA
}

func (key *RSAKey) Sign(v interface{}) (signature []byte, err error) {
	digest, err := tlv.Hash(sha256.New, v)
	if err != nil {
		return
	}
	signature, err = rsa.SignPKCS1v15(rand.Reader, key.PrivateKey, crypto.SHA256, digest)
	return
}

func (key *RSAKey) Verify(v interface{}, signature []byte) (err error) {
	digest, err := tlv.Hash(sha256.New, v)
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
