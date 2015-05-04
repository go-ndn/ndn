package ndn

import (
	"bytes"
	"io/ioutil"
	"reflect"
	"testing"
)

var (
	rsaKey   = readKey("key/default.pri")
	ecdsaKey = readKey("key/ecdsa.pri")
)

func readKey(file string) (key Key) {
	pem, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	key.DecodePrivateKey(pem)
	return
}

func TestPrivateKey(t *testing.T) {
	for _, key1 := range []Key{rsaKey, ecdsaKey} {
		buf := new(bytes.Buffer)
		err := key1.EncodePrivateKey(buf)
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
}

func TestCertificate(t *testing.T) {
	for _, key1 := range []Key{rsaKey, ecdsaKey} {
		buf := new(bytes.Buffer)
		err := key1.EncodeCertificate(buf)
		if err != nil {
			t.Fatal(err)
		}

		var key2 Key
		err = key2.DecodeCertificate(buf)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSignVerify(t *testing.T) {
	d := new(Data)
	for _, key := range []Key{rsaKey, ecdsaKey} {
		err := key.SignData(d)
		if err != nil {
			t.Fatal(err)
		}
		err = key.Verify(d, d.SignatureValue)
		if err != nil {
			t.Fatal(err)
		}
	}
}
