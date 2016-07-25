package ndn

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"time"

	"github.com/go-ndn/tlv"
)

// Errors introduced by Key.
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

// Key signs and verifies data packets.
type Key interface {
	Locator() Name
	SignatureType() uint64
	// If the key is symmetric, Private is identical to Public.
	Private() ([]byte, error)
	Public() ([]byte, error)

	Sign(interface{}) ([]byte, error)
	Verify(interface{}, []byte) error
}

// EncodePrivateKey encodes the private key in PEM encoding.
//
// See DecodePrivateKey.
func EncodePrivateKey(key Key, w io.Writer) (err error) {
	var keyType string
	switch key.SignatureType() {
	case SignatureTypeSHA256WithRSA:
		keyType = pemTypeRSA
	case SignatureTypeSHA256WithECDSA:
		keyType = pemTypeECDSA
	case SignatureTypeSHA256WithHMAC:
		keyType = pemTypeHMAC
	default:
		err = ErrNotSupported
		return
	}
	keyBytes, err := key.Private()
	if err != nil {
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

// DecodePrivateKey decodes the private key in PEM encoding.
//
// See EncodePrivateKey.
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

// CertificateToData creates a data packet from a self-signed public key.
//
// See CertificateFromData.
func CertificateToData(key Key) (d *Data, err error) {
	d = &Data{
		Name: key.Locator(),
		MetaInfo: MetaInfo{
			ContentType:     2,       // key
			FreshnessPeriod: 3600000, // 1 hour
		},
	}
	d.Content, err = key.Public()
	if err != nil {
		return
	}
	err = SignData(key, d)
	return
}

// EncodeCertificate invokes CertificateToData and encodes
// this data packet in base64 encoding.
//
// See DecodeCertificate.
func EncodeCertificate(key Key, w io.Writer) (err error) {
	d, err := CertificateToData(key)
	if err != nil {
		return
	}
	enc := base64.NewEncoder(base64.StdEncoding, w)
	err = d.WriteTo(tlv.NewWriter(enc))
	if err != nil {
		return
	}
	enc.Close()
	return
}

// CertificateFromData creates a public key from a data packet.
//
// See CertificateToData.
func CertificateFromData(d *Data) (key Key, err error) {
	pub, err := x509.ParsePKIXPublicKey(d.Content)
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

// DecodeCertificate decodes a data packet in base64 encoding,
// and invokes CertificateFromData.
//
// See EncodeCertificate.
func DecodeCertificate(r io.Reader) (key Key, err error) {
	d := new(Data)
	err = d.ReadFrom(tlv.NewReader(base64.NewDecoder(base64.StdEncoding, r)))
	if err != nil {
		return
	}
	return CertificateFromData(d)
}

// SignData signs a data packet with the given key.
func SignData(key Key, d *Data) (err error) {
	d.SignatureInfo.SignatureType = key.SignatureType()
	d.SignatureInfo.KeyLocator.Name = key.Locator()
	d.SignatureValue, err = key.Sign(d)
	return
}

// VerifyData verifies a data packet with the given key.
//
// It also checks ValidityPeriod.
func VerifyData(key Key, d *Data) error {
	now := time.Now()
	if d.SignatureInfo.ValidityPeriod.NotBefore != "" {
		t, err := time.Parse(ISO8601, d.SignatureInfo.ValidityPeriod.NotBefore)
		if err != nil || now.Before(t) {
			return ErrInvalidSignature
		}
	}
	if d.SignatureInfo.ValidityPeriod.NotAfter != "" {
		t, err := time.Parse(ISO8601, d.SignatureInfo.ValidityPeriod.NotAfter)
		if err != nil || now.After(t) {
			return ErrInvalidSignature
		}
	}
	return key.Verify(d, d.SignatureValue)
}
