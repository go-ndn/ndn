package ndn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
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
	pemTypeHMAC   = "HMAC PRIVATE KEY"
)

type Key interface {
	Locator() Name
	SignatureType() uint64
	Private() crypto.PrivateKey
	Public() crypto.PublicKey

	Sign(interface{}) ([]byte, error)
	Verify(interface{}, []byte) error
}

func EncodePrivateKey(key Key, w io.Writer) (err error) {
	var keyType string
	var keyBytes []byte
	switch pri := key.Private().(type) {
	case *rsa.PrivateKey:
		keyType = pemTypeRSA
		keyBytes = x509.MarshalPKCS1PrivateKey(pri)
	case *ecdsa.PrivateKey:
		keyType = pemTypeECDSA
		keyBytes, err = x509.MarshalECPrivateKey(pri)
		if err != nil {
			return
		}
	case *HMACKey:
		keyType = pemTypeHMAC
		keyBytes = pri.PrivateKey
	default:
		err = ErrNotSupported
		return
	}
	err = pem.Encode(w, &pem.Block{
		Type: keyType,
		Headers: map[string]string{
			pemHeaderName: key.Locator().String(),
		},
		Bytes: keyBytes,
	})
	return
}

func DecodePrivateKey(r io.Reader) (key Key, err error) {
	pemData, err := ioutil.ReadAll(r)
	if err != nil {
		return
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		err = ErrInvalidPEM
		return
	}
	name := NewName(block.Headers[pemHeaderName])
	switch block.Type {
	case pemTypeRSA:
		var pri *rsa.PrivateKey
		pri, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return
		}
		key = &RSAKey{
			Name:       name,
			PrivateKey: pri,
		}
	case pemTypeECDSA:
		var pri *ecdsa.PrivateKey
		pri, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return
		}
		key = &ECDSAKey{
			Name:       name,
			PrivateKey: pri,
		}
	case pemTypeHMAC:
		key = &HMACKey{
			Name:       name,
			PrivateKey: block.Bytes,
		}
	default:
		err = ErrNotSupported
	}
	return
}

type certificate struct {
	Validity      validity
	Subject       []pkix.AttributeTypeAndValue
	PublicKeyInfo asn1.RawValue
}

type validity struct {
	NotBefore, NotAfter time.Time
}

func EncodeCertificate(key Key, w io.Writer) (err error) {
	d := &Data{
		Name: key.Locator(),
		MetaInfo: MetaInfo{
			ContentType: 2, //key
		},
	}
	keyBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
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
	err = SignData(key, d)
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

func DecodeCertificate(r io.Reader) (key Key, err error) {
	var d Data
	err = d.ReadFrom(tlv.NewReader(base64.NewDecoder(base64.StdEncoding, r)))
	if err != nil {
		return
	}
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
		key = &RSAKey{
			Name: d.Name,
			PrivateKey: &rsa.PrivateKey{
				PublicKey: *pub,
			},
		}
	case *ecdsa.PublicKey:
		key = &ECDSAKey{
			Name: d.Name,
			PrivateKey: &ecdsa.PrivateKey{
				PublicKey: *pub,
			},
		}
	default:
		err = ErrNotSupported
	}
	return
}

func SignData(key Key, d *Data) (err error) {
	d.SignatureInfo.SignatureType = key.SignatureType()
	d.SignatureInfo.KeyLocator.Name = key.Locator()
	d.SignatureValue, err = key.Sign(d)
	return
}
