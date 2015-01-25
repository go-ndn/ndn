package ndn

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"
)

var (
	SignKey Key
)

type Key struct {
	Name       Name
	PrivateKey crypto.PrivateKey
}

// DecodePrivateKey reads key from pem bytes
func (this *Key) DecodePrivateKey(pemData []byte) (err error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		err = fmt.Errorf("not pem data")
		return
	}
	this.Name = NewName(block.Headers["NAME"])
	switch block.Type {
	case "RSA PRIVATE KEY":
		this.PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "ECDSA PRIVATE KEY":
		this.PrivateKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		err = fmt.Errorf("unsupported key type")
	}
	return
}

// EncodePrivateKey writes key to io.Writer
func (this *Key) EncodePrivateKey(buf io.Writer) (err error) {
	var keyBytes []byte
	var keyType string
	switch key := this.PrivateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
		keyType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return
		}
		keyType = "ECDSA PRIVATE KEY"
	default:
		err = fmt.Errorf("unsupported key type")
		return
	}
	err = pem.Encode(buf, &pem.Block{
		Type: keyType,
		Headers: map[string]string{
			"NAME": this.Name.String(),
		},
		Bytes: keyBytes,
	})
	return
}

// SignatureType shows key type in ndn signature type
//
// If the key is not initialized, it will return SignatureTypeDigestSha256.
func (this *Key) SignatureType() uint64 {
	switch this.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return SignatureTypeSha256WithRsa
	case *ecdsa.PrivateKey:
		return SignatureTypeSha256WithEcdsa
	}
	return SignatureTypeDigestSha256
}

func (this *Key) EncodeCertificate(buf io.Writer) (err error) {
	d := &Data{
		Name: this.Name,
		MetaInfo: MetaInfo{
			ContentType: 2, //key
		},
	}
	var keyBytes []byte
	switch key := this.PrivateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return
		}
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return
		}
	default:
		err = fmt.Errorf("unsupported key type")
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
	enc := base64.NewEncoder(base64.StdEncoding, buf)
	err = d.WriteTo(enc)
	if err != nil {
		return
	}
	enc.Close()
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

func (this *Key) DecodeCertificate(buf io.Reader) (err error) {
	var d Data
	err = d.ReadFrom(bufio.NewReader(base64.NewDecoder(base64.StdEncoding, buf)))
	if err != nil {
		return
	}
	this.Name = d.Name
	var cert certificate
	_, err = asn1.Unmarshal(d.Content, &cert)
	if err != nil {
		return
	}
	pub, err := x509.ParsePKIXPublicKey(cert.PublicKeyInfo.FullBytes)
	if err != nil {
		return
	}
	switch key := pub.(type) {
	case *rsa.PublicKey:
		this.PrivateKey = &rsa.PrivateKey{
			PublicKey: *key,
		}
	case *ecdsa.PublicKey:
		this.PrivateKey = &ecdsa.PrivateKey{
			PublicKey: *key,
		}
	default:
		err = fmt.Errorf("unsupported key type")
	}
	return
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (this *Key) sign(v interface{}) (signature []byte, err error) {
	digest, err := newSha256(v)
	if err != nil {
		return
	}
	switch key := this.PrivateKey.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	case *ecdsa.PrivateKey:
		var sig ecdsaSignature
		sig.R, sig.S, err = ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			return
		}
		signature, err = asn1.Marshal(sig)
	default:
		err = fmt.Errorf("unsupported key type")
	}
	return
}

func (this *Key) Verify(v interface{}, signature []byte) (err error) {
	digest, err := newSha256(v)
	if err != nil {
		return
	}
	switch key := this.PrivateKey.(type) {
	case *rsa.PrivateKey:
		err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest, signature)
		if err != nil {
			return
		}
	case *ecdsa.PrivateKey:
		var sig ecdsaSignature
		_, err = asn1.Unmarshal(signature, &sig)
		if err != nil {
			return
		}
		if !ecdsa.Verify(&key.PublicKey, digest, sig.R, sig.S) {
			err = fmt.Errorf("crypto/ecdsa: verification error")
		}
	default:
		err = fmt.Errorf("unsupported key type")
	}
	return
}
