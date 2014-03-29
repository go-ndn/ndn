package ndn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var (
	rsaPrivateKey *rsa.PrivateKey
)

func ReadRSAKey(pemData []byte) (err error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		err = errors.New(NOT_RSA_PRIVATE_KEY)
		return
	}
	// Decode the RSA private key
	rsaPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	return
}

func WriteRSAKey() (pemData []byte, err error) {
	if rsaPrivateKey == nil {
		err = errors.New(NOT_RSA_PRIVATE_KEY)
		return
	}
	pemData = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey),
	})
	return
}

func GenerateRSAKey() (err error) {
	rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 1024)
	return
}

func signRSA(l []TLV) (signature []byte, err error) {
	if rsaPrivateKey == nil {
		err = errors.New(NOT_RSA_PRIVATE_KEY)
		return
	}
	digest, err := newSHA256(l)
	if err != nil {
		return
	}
	signature, err = rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA256, digest)
	return
}

func verifyRSA(l []TLV, signature []byte) bool {
	if rsaPrivateKey == nil {
		return false
	}
	digest, err := newSHA256(l)
	if err != nil {
		return false
	}
	return nil == rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA256, digest, signature)
}
