package ndn

import (
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
	"io"
	"math/big"
	"time"

	"github.com/go-ndn/tlv"
)

var (
	ErrNotSupported     = errors.New("feature not supported")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrInvalidPEM       = errors.New("invalid pem")
)

const (
	pemHeaderName = "NAME"
	pemTypeRSA    = "RSA PRIVATE KEY"
	pemTypeECDSA  = "ECDSA PRIVATE KEY"
)

type Key struct {
	Name       Name
	PrivateKey crypto.PrivateKey
}

// DecodePrivateKey reads key from pem bytes
func (key *Key) DecodePrivateKey(pemData []byte) (err error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		err = ErrInvalidPEM
		return
	}
	key.Name = NewName(block.Headers[pemHeaderName])
	switch block.Type {
	case pemTypeRSA:
		key.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case pemTypeECDSA:
		key.PrivateKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		err = ErrNotSupported
	}
	return
}

// EncodePrivateKey writes key to io.Writer
func (key *Key) EncodePrivateKey(w io.Writer) (err error) {
	var keyBytes []byte
	var keyType string
	switch pri := key.PrivateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(pri)
		keyType = pemTypeRSA
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(pri)
		if err != nil {
			return
		}
		keyType = pemTypeECDSA
	default:
		err = ErrNotSupported
		return
	}
	err = pem.Encode(w, &pem.Block{
		Type: keyType,
		Headers: map[string]string{
			pemHeaderName: key.Name.String(),
		},
		Bytes: keyBytes,
	})
	return
}

// SignatureType shows key type in ndn signature type
//
// If the key is not initialized, it will return SignatureTypeDigestSHA256.
func (key *Key) SignatureType() uint64 {
	switch key.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return SignatureTypeSHA256WithRSA
	case *ecdsa.PrivateKey:
		return SignatureTypeSHA256WithECDSA
	}
	return SignatureTypeDigestSHA256
}

type certificate struct {
	Validity      validity
	Subject       []pkix.AttributeTypeAndValue
	PublicKeyInfo asn1.RawValue
}

type validity struct {
	NotBefore, NotAfter time.Time
}

func (key *Key) EncodeCertificate(w io.Writer) (err error) {
	d := &Data{
		Name: key.Name,
		MetaInfo: MetaInfo{
			ContentType: 2, //key
		},
	}
	var keyBytes []byte
	switch pri := key.PrivateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes, err = x509.MarshalPKIXPublicKey(&pri.PublicKey)
		if err != nil {
			return
		}
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalPKIXPublicKey(&pri.PublicKey)
		if err != nil {
			return
		}
	default:
		err = ErrNotSupported
		return
	}
	d.Content, err = asn1.Marshal(certificate{
		Validity: validity{
			NotBefore: time.Now().UTC(),
			NotAfter:  time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC), // end of asn.1
		},
		Subject: []pkix.AttributeTypeAndValue{{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 41},
			Value: "go ndn",
		}},
		PublicKeyInfo: asn1.RawValue{FullBytes: keyBytes},
	})
	if err != nil {
		return
	}
	err = key.SignData(d)
	if err != nil {
		return
	}
	enc := base64.NewEncoder(base64.StdEncoding, w)
	err = d.WriteTo(enc)
	if err != nil {
		return
	}
	enc.Close()
	return
}

func (key *Key) DecodeCertificate(r io.Reader) (err error) {
	var d Data
	err = d.ReadFrom(tlv.NewReader(base64.NewDecoder(base64.StdEncoding, r)))
	if err != nil {
		return
	}
	key.Name = d.Name
	var cert certificate
	_, err = asn1.Unmarshal(d.Content, &cert)
	if err != nil {
		return
	}
	pub, err := x509.ParsePKIXPublicKey(cert.PublicKeyInfo.FullBytes)
	if err != nil {
		return
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		key.PrivateKey = &rsa.PrivateKey{
			PublicKey: *pub,
		}
	case *ecdsa.PublicKey:
		key.PrivateKey = &ecdsa.PrivateKey{
			PublicKey: *pub,
		}
	default:
		err = ErrNotSupported
	}
	return
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (key *Key) SignData(d *Data) (err error) {
	d.SignatureInfo.SignatureType = key.SignatureType()
	d.SignatureInfo.KeyLocator.Name = key.Name
	d.SignatureValue, err = key.Sign(d)
	return
}

func (key *Key) Sign(v interface{}) (signature []byte, err error) {
	digest, err := NewSHA256(v)
	if err != nil {
		return
	}
	switch pri := key.PrivateKey.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, pri, crypto.SHA256, digest)
	case *ecdsa.PrivateKey:
		var sig ecdsaSignature
		sig.R, sig.S, err = ecdsa.Sign(rand.Reader, pri, digest)
		if err != nil {
			return
		}
		signature, err = asn1.Marshal(sig)
	default:
		err = ErrNotSupported
	}
	return
}

func (key *Key) Verify(v interface{}, signature []byte) (err error) {
	digest, err := NewSHA256(v)
	if err != nil {
		return
	}
	switch pri := key.PrivateKey.(type) {
	case *rsa.PrivateKey:
		err = rsa.VerifyPKCS1v15(&pri.PublicKey, crypto.SHA256, digest, signature)
		if err != nil {
			err = ErrInvalidSignature
			return
		}
	case *ecdsa.PrivateKey:
		var sig ecdsaSignature
		_, err = asn1.Unmarshal(signature, &sig)
		if err != nil {
			return
		}
		if !ecdsa.Verify(&pri.PublicKey, digest, sig.R, sig.S) {
			err = ErrInvalidSignature
			return
		}
	default:
		err = ErrNotSupported
	}
	return
}
