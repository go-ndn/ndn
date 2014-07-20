package ndn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
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
	"strings"
	"time"
)

var (
	SignKey   Key
	VerifyKey Key
)

type Key struct {
	Name       Name
	privateKey crypto.PrivateKey
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
	parts := strings.SplitN(block.Type, " ", 2)
	if len(parts) != 2 {
		err = errors.New("missing key type or name")
		return
	}
	this.Name.Set(parts[1])
	switch parts[0] {
	case "rsa":
		this.privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "ecdsa":
		this.privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		err = errors.New("unsupported key type")
	}
	return
}

func (this *Key) Encode() (pemData []byte, err error) {
	var b []byte
	var keyType string
	switch this.privateKey.(type) {
	case (*rsa.PrivateKey):
		b = x509.MarshalPKCS1PrivateKey(this.privateKey.(*rsa.PrivateKey))
		keyType = "rsa"
	case (*ecdsa.PrivateKey):
		b, err = x509.MarshalECPrivateKey(this.privateKey.(*ecdsa.PrivateKey))
		if err != nil {
			return
		}
		keyType = "ecdsa"
	default:
		err = errors.New("unsupported key type")
		return
	}
	pemData = pem.EncodeToMemory(&pem.Block{
		Type:  keyType + " " + this.Name.String(),
		Bytes: b,
	})
	return
}

var (
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

func (this *Key) EncodeCertificate() (raw []byte, err error) {
	var sigType uint64
	var publicKeyBytes []byte
	var oidSig asn1.ObjectIdentifier
	switch this.privateKey.(type) {
	case (*rsa.PrivateKey):
		publicKeyBytes, err = asn1.Marshal(this.privateKey.(*rsa.PrivateKey).PublicKey)
		if err != nil {
			return
		}
		oidSig = oidSignatureSHA256WithRSA
		sigType = SignatureTypeSha256WithRsa
	case (*ecdsa.PrivateKey):
		publicKeyBytes, err = asn1.Marshal(this.privateKey.(*rsa.PrivateKey).PublicKey)
		if err != nil {
			return
		}
		oidSig = oidSignatureECDSAWithSHA256
		sigType = SignatureTypeSha256WithEcdsa
	default:
		err = errors.New("unsupported key type")
		return
	}

	d := Data{
		Name: this.LocatorName(),
		MetaInfo: MetaInfo{
			ContentType: 2, //key
		},
		SignatureInfo: SignatureInfo{
			SignatureType: sigType,
			KeyLocator: KeyLocator{
				Name: this.LocatorName(),
			},
		},
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
				Algorithm: oidSig,
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

func NewKey(name string, privateKey crypto.PrivateKey) (key Key, err error) {
	key.Name.Set(name)
	switch privateKey.(type) {
	case (*rsa.PrivateKey):
	case (*ecdsa.PrivateKey):
	default:
		err = errors.New("unsupported key type")
		return
	}
	key.privateKey = privateKey
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

type ecdsaSignature struct {
	r, s *big.Int
}

func (this *Key) Sign(digest []byte) (signature []byte, err error) {
	switch this.privateKey.(type) {
	case (*rsa.PrivateKey):
		signature, err = rsa.SignPKCS1v15(rand.Reader, this.privateKey.(*rsa.PrivateKey), crypto.SHA256, digest)
	case (*ecdsa.PrivateKey):
		var sig ecdsaSignature
		sig.r, sig.s, err = ecdsa.Sign(rand.Reader, this.privateKey.(*ecdsa.PrivateKey), digest)
		if err != nil {
			return
		}
		signature, err = asn1.Marshal(sig)
	default:
		err = errors.New("unsupported key type")
	}
	return
}
