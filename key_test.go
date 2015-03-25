package ndn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
)

func TestPrivateKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key1 := Key{
		Name:       NewName("/testing/key"),
		PrivateKey: rsaKey,
	}

	buf := new(bytes.Buffer)
	err = key1.EncodePrivateKey(buf)
	if err != nil {
		t.Fatal(err)
	}

	var key2 Key
	err = key2.DecodePrivateKey(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(key1, key2) {
		t.Fatal("not equal", key1, key2)
	}
}

func TestCertificate(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key1 := Key{
		Name:       NewName("/testing/key"),
		PrivateKey: rsaKey,
	}

	buf := new(bytes.Buffer)
	err = key1.EncodeCertificate(buf)
	if err != nil {
		t.Fatal(err)
	}

	var key2 Key
	err = key2.DecodeCertificate(buf)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignVerify(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := Key{
		Name:       NewName("/testing/key"),
		PrivateKey: ecdsaKey,
	}

	d := new(Data)
	err = key.Sign(d)
	if err != nil {
		t.Fatal(err)
	}
	err = key.Verify(d, d.SignatureValue)
	if err != nil {
		t.Fatal(err)
	}
}
