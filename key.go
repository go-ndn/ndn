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
	privateKey crypto.PrivateKey
}

// Decode reads key from pem bytes
func (this *Key) Decode(pemData []byte) (err error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		err = fmt.Errorf("not pem data")
		return
	}
	this.Name = NewName(block.Headers["NAME"])
	switch block.Type {
	case "RSA PRIVATE KEY":
		this.privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "ECDSA PRIVATE KEY":
		this.privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		err = fmt.Errorf("unsupported key type")
	}
	return
}

// Encode writes key to io.Writer
func (this *Key) Encode(buf io.Writer) (err error) {
	var b []byte
	var keyType string
	switch key := this.privateKey.(type) {
	case *rsa.PrivateKey:
		b = x509.MarshalPKCS1PrivateKey(key)
		keyType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		b, err = x509.MarshalECPrivateKey(key)
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
		Bytes: b,
	})
	return
}

var (
	oidRsa   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidEcdsa = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// SignatureType shows key type in ndn signature type
//
// If the key is not initialized, it will return SignatureTypeDigestSha256.
func (this *Key) SignatureType() uint64 {
	switch this.privateKey.(type) {
	case *rsa.PrivateKey:
		return SignatureTypeSha256WithRsa
	case *ecdsa.PrivateKey:
		return SignatureTypeSha256WithEcdsa
	}
	return SignatureTypeDigestSha256
}

func (this *Key) Certificate() (c *certificate, err error) {
	var publicKeyBytes []byte
	var oidSig asn1.ObjectIdentifier
	switch key := this.privateKey.(type) {
	case *rsa.PrivateKey:
		publicKeyBytes, err = asn1.Marshal(key.PublicKey)
		if err != nil {
			return
		}
		oidSig = oidRsa
	case *ecdsa.PrivateKey:
		publicKeyBytes, err = asn1.Marshal(key.PublicKey)
		if err != nil {
			return
		}
		oidSig = oidEcdsa
	default:
		err = fmt.Errorf("unsupported key type")
		return
	}
	c = &certificate{
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
	}
	return
}

func (this *Key) EncodeCertificate(buf io.Writer) (err error) {
	d := &Data{
		Name: this.Name.CertName(),
		MetaInfo: MetaInfo{
			ContentType: 2, //key
		},
	}
	c, err := this.Certificate()
	if err != nil {
		return
	}
	d.Content, err = asn1.Marshal(c)
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

// NewKey creates a new key with name and private key
//
// Supported algorithms are rsa and ecdsa.
func NewKey(name string, privateKey crypto.PrivateKey) (key Key, err error) {
	key.Name = NewName(name)
	switch privateKey.(type) {
	case *rsa.PrivateKey:
	case *ecdsa.PrivateKey:
	default:
		err = fmt.Errorf("unsupported key type")
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

func PrintCertificate(buf io.Reader) (err error) {
	// newline will be ignored
	d := new(Data)
	err = d.ReadFrom(bufio.NewReader(base64.NewDecoder(base64.StdEncoding, buf)))
	if err != nil {
		return
	}
	c := new(certificate)
	_, err = asn1.Unmarshal(d.Content, c)
	if err != nil {
		return
	}
	Print(d, c)
	return
}

func (this *Key) DecodePubKey(raw []byte) (err error) {
	cert := new(certificate)
	_, err = asn1.Unmarshal(raw, cert)
	if err != nil {
		return
	}
	switch cert.SubjectPubKeyInfo.AlgorithmIdentifier.Algorithm.String() {
	case oidRsa.String():
		var pri rsa.PrivateKey
		_, err = asn1.Unmarshal(cert.SubjectPubKeyInfo.Bytes.Bytes, &pri.PublicKey)
		if err != nil {
			return
		}
		this.privateKey = &pri
	case oidEcdsa.String():
		var pri ecdsa.PrivateKey
		_, err = asn1.Unmarshal(cert.SubjectPubKeyInfo.Bytes.Bytes, &pri.PublicKey)
		if err != nil {
			return
		}
		this.privateKey = &pri
	default:
		err = fmt.Errorf("unsupported key type")
	}
	return
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (this *Key) Sign(digest []byte) (signature []byte, err error) {
	switch key := this.privateKey.(type) {
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

func (this *Key) Verify(digest, signature []byte) error {
	switch key := this.privateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest, signature)
	case *ecdsa.PrivateKey:
		var sig ecdsaSignature
		_, err := asn1.Unmarshal(signature, &sig)
		if err != nil {
			return err
		}
		if ecdsa.Verify(&key.PublicKey, digest, sig.R, sig.S) {
			return nil
		} else {
			return fmt.Errorf("crypto/ecdsa: verification error")
		}
	default:
		return fmt.Errorf("unsupported key type")
	}
}
