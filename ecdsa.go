package ndn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"

	"github.com/go-ndn/tlv"
)

type ECDSAKey struct {
	Name Name
	*ecdsa.PrivateKey
}

func (key *ECDSAKey) Locator() Name {
	return key.Name
}

func (key *ECDSAKey) Private() crypto.PrivateKey {
	return key.PrivateKey
}

func (key *ECDSAKey) SignatureType() uint64 {
	return SignatureTypeSHA256WithECDSA
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (key *ECDSAKey) Sign(v interface{}) (signature []byte, err error) {
	digest, err := tlv.Hash(sha256.New, v)
	if err != nil {
		return
	}
	var sig ecdsaSignature
	sig.R, sig.S, err = ecdsa.Sign(rand.Reader, key.PrivateKey, digest)
	if err != nil {
		return
	}
	signature, err = asn1.Marshal(sig)
	return
}

func (key *ECDSAKey) Verify(v interface{}, signature []byte) (err error) {
	digest, err := tlv.Hash(sha256.New, v)
	if err != nil {
		return
	}
	var sig ecdsaSignature
	_, err = asn1.Unmarshal(signature, &sig)
	if err != nil {
		return
	}
	if !ecdsa.Verify(&key.PrivateKey.PublicKey, digest, sig.R, sig.S) {
		err = ErrInvalidSignature
		return
	}
	return
}
