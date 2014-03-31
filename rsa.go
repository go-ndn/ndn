package ndn

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	//"github.com/davecgh/go-spew/spew"
	"time"
)

var (
	rsaPrivateKey *rsa.PrivateKey
)

type Certificate struct {
	Validity          Validity
	Subject           []pkix.AttributeTypeAndValue
	SubjectPubKeyInfo SubjectPubKeyInfo
}

type Validity struct {
	NotAfter  time.Time
	NotBefore time.Time
}

type SubjectPubKeyInfo struct {
	AlgorithmIdentifier pkix.AlgorithmIdentifier
	Bytes               asn1.BitString
}

func ReadCertificate(raw []byte) (cert *Certificate, err error) {
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
	cert = &Certificate{}
	_, err = asn1.Unmarshal(d.Content, cert)
	return
}

func WriteCertificate() (raw []byte, err error) {
	if rsaPrivateKey == nil {
		err = errors.New(NOT_RSA_PRIVATE_KEY)
		return
	}
	d := Data{
		Name: [][]byte{
			[]byte("testing"),
			[]byte("KEY"),
			[]byte("ksk"),
			[]byte("ID-CERT"),
			[]byte{0x1},
		},
		MetaInfo: MetaInfo{
			ContentType: CONTENT_TYPE_KEY,
		},
		Signature: Signature{
			Type: SIGNATURE_TYPE_SIGNATURE_SHA_256_WITH_RSA,
			Info: []TLV{
				{Type: KEY_LOCATOR, Children: []TLV{
					nameEncode([][]byte{
						[]byte("testing"),
						[]byte("KEY"),
						[]byte("ksk"),
						[]byte("ID-CERT"),
					}),
				}},
			},
		},
	}
	d.Content, err = asn1.Marshal(Certificate{
		Validity: Validity{
			NotBefore: time.Now(),
			NotAfter:  time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC), // end of asn.1
		},
		Subject: []pkix.AttributeTypeAndValue{{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 41},
			Value: "testing/KEY/ksk/ID-CERT",
		}},
		SubjectPubKeyInfo: SubjectPubKeyInfo{
			AlgorithmIdentifier: pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, //rsa
				Parameters: asn1.RawValue{
					Tag: 5,
				},
			},
			Bytes: asn1.BitString{
				Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey),
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
	buf := bytes.NewBufferString(base64.StdEncoding.EncodeToString(b))
	out := new(bytes.Buffer)
	for {
		if buf.Len() == 0 {
			break
		}
		out.Write(buf.Next(64))
		out.WriteByte(0xA)
	}
	raw = out.Bytes()
	return
}

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
