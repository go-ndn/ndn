package ndn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/davecgh/go-spew/spew"
	"math/big"
	"time"
)

var (
	SignKey   *rsa.PrivateKey
	VerifyKey *rsa.PrivateKey
)

type certificate struct {
	Validity          validity
	Subject           []pkix.AttributeTypeAndValue
	SubjectPubKeyInfo subjectPubKeyInfo
}

type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

type subjectPubKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	Bytes               asn1.BitString
}

type rsaPublicKey struct {
	N *big.Int
	E int
}

func PrintCertificate(raw []byte) (err error) {
	// newline does not matter
	b, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return
	}
	d := Data{}
	err = d.Decode(b)
	//spew.Dump(d)
	if err != nil {
		return
	}
	cert := &certificate{}
	_, err = asn1.Unmarshal(d.Content, cert)
	if err != nil {
		return
	}
	spew.Dump(cert)
	return
}

func WriteCertificate(key *rsa.PrivateKey) (raw []byte, err error) {
	d := Data{
		Name: nameFromString("/testing/KEY/pubkey/ID-CERT"),
		MetaInfo: MetaInfo{
			ContentType: CONTENT_TYPE_KEY,
		},
		Signature: Signature{
			Type: SIGNATURE_TYPE_SIGNATURE_SHA_256_WITH_RSA,
			Info: []TLV{
				{Type: KEY_LOCATOR, Children: []TLV{
					nameEncode(nameFromString("/testing/KEY/pubkey/ID-CERT")),
				}},
			},
		},
	}
	publicKeyBytes, err := asn1.Marshal(rsaPublicKey{
		N: key.PublicKey.N,
		E: key.PublicKey.E,
	})
	if err != nil {
		return
	}
	d.Content, err = asn1.Marshal(certificate{
		Validity: validity{
			NotBefore: time.Now(),
			NotAfter:  time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC), // end of asn.1
		},
		Subject: []pkix.AttributeTypeAndValue{{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 41},
			Value: "/testing/pubkey",
		}},
		SubjectPubKeyInfo: subjectPubKeyInfo{
			AlgorithmIdentifier: pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, //rsa
				// This is a NULL parameters value which is technically
				// superfluous, but most other code includes it and, by
				// doing this, we match their public key hashes.
				Parameters: asn1.RawValue{
					Tag: 5,
				},
			},
			Bytes: asn1.BitString{
				Bytes:     publicKeyBytes,
				BitLength: 8 * len(publicKeyBytes),
			},
		},
	})
	if err != nil {
		return
	}
	b, err := d.Encode()
	if err != nil {
		return
	}
	raw = []byte(base64.StdEncoding.EncodeToString(b))
	return
}

func ReadRSAKey(pemData []byte) (key *rsa.PrivateKey, err error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		err = errors.New("rsa private key not found")
		return
	}
	// Decode the RSA private key
	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	return
}

func WriteRSAKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

func GenerateRSAKey() (key *rsa.PrivateKey, err error) {
	key, err = rsa.GenerateKey(rand.Reader, 2048)
	return
}

func signRSA(l []TLV) (signature []byte, err error) {
	if SignKey == nil {
		err = errors.New("signKey not found")
		return
	}
	digest, err := newSHA256(l)
	if err != nil {
		return
	}
	signature, err = rsa.SignPKCS1v15(rand.Reader, SignKey, crypto.SHA256, digest)
	return
}

func verifyRSA(l []TLV, signature []byte) bool {
	if VerifyKey == nil {
		return false
	}
	digest, err := newSHA256(l)
	if err != nil {
		return false
	}
	return nil == rsa.VerifyPKCS1v15(&VerifyKey.PublicKey, crypto.SHA256, digest, signature)
}
