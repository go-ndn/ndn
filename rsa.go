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
	"github.com/davecgh/go-spew/spew"
	"math/big"
	"time"
)

var (
	SignKey   Key
	VerifyKey Key
)

type Key struct {
	Name Name
	*rsa.PrivateKey
}

func (this *Key) LocatorName() (name Name) {
	for i := 0; i < len(this.Name.Components); i++ {
		if i == len(this.Name.Components)-1 {
			name.Components = append(name.Components, []byte("KEY"))
		}
		name.Components = append(name.Components, this.Name.Components[i])
	}
	name.Components = append(name.Components, []byte("ID-CERT"))
	return
}

func (this *Key) Decode(pemData []byte) (err error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		err = errors.New("not pem data")
		return
	}
	this.Name.Set(block.Type)
	// Decode the RSA private key
	this.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	return
}

func (this *Key) Encode() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  this.Name.String(),
		Bytes: x509.MarshalPKCS1PrivateKey(this.PrivateKey),
	})
}

func (this *Key) EncodeCertificate() (raw []byte, err error) {
	d := Data{
		Name: this.LocatorName(),
		MetaInfo: MetaInfo{
			ContentType: 2, //key
		},
		SignatureInfo: SignatureInfo{
			SignatureType: SignatureTypeSha256Rsa,
			KeyLocator: KeyLocator{
				Name: this.LocatorName(),
			},
		},
	}
	publicKeyBytes, err := asn1.Marshal(rsaPublicKey{
		N: this.PublicKey.N,
		E: this.PublicKey.E,
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
			Value: this.Name.String(),
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

	buf := bytes.NewBufferString(base64.StdEncoding.EncodeToString(b))
	buf2 := new(bytes.Buffer)
	for buf.Len() != 0 {
		buf2.Write(buf.Next(64))
		buf2.WriteByte(0xA)
	}
	raw = buf2.Bytes()
	return
}

func NewKey(name string) (key Key, err error) {
	key.Name.Set(name)
	key.PrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	return
}

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

func signRSA(digest []byte) (signature []byte, err error) {
	if SignKey.PrivateKey == nil {
		err = errors.New("signKey not found")
		return
	}
	signature, err = rsa.SignPKCS1v15(rand.Reader, SignKey.PrivateKey, crypto.SHA256, digest)
	return
}
