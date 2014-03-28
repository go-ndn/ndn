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
	RSAPrivateKey *rsa.PrivateKey
)

func ReadRSAKey(pemData []byte) (err error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		err = errors.New(NOT_RSA_PRIVATE_KEY)
		return
	}
	// Decode the RSA private key
	RSAPrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	return
}

func WriteRSAKey() (pemData []byte, err error) {
	if RSAPrivateKey == nil {
		err = errors.New(NOT_RSA_PRIVATE_KEY)
		return
	}
	pemData = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(RSAPrivateKey),
	})
	return
}

func GenerateRSAKey() (err error) {
	RSAPrivateKey, err = rsa.GenerateKey(rand.Reader, 1024)
	return
}

func SignRSA(l []TLV) (signature []byte, err error) {
	if RSAPrivateKey == nil {
		err = errors.New(NOT_RSA_PRIVATE_KEY)
		return
	}
	digest, err := NewSHA256(l)
	if err != nil {
		return
	}
	signature, err = rsa.SignPKCS1v15(rand.Reader, RSAPrivateKey, crypto.SHA256, digest)
	return
}

func VerifyRSA(l []TLV, signature []byte) bool {
	if RSAPrivateKey == nil {
		return false
	}
	digest, err := NewSHA256(l)
	if err != nil {
		return false
	}
	return nil == rsa.VerifyPKCS1v15(&RSAPrivateKey.PublicKey, crypto.SHA256, digest, signature)
}
