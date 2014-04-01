package ndn

import (
	"bytes"
	//"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"os"
	"testing"
)

func TestRSA(t *testing.T) {
	rsaPrivateKey = nil
	_, err := WriteRSAKey()
	if err == nil {
		t.Error("RSA key should be empty")
	}
	GenerateRSAKey()
	b, err := WriteRSAKey()
	if err != nil {
		t.Error(err)
	}
	err = ReadRSAKey(b)
	if err != nil {
		t.Error(err)
	}
	b2, err := WriteRSAKey()
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(b, b2) {
		t.Error("RSA key should be the same")
	}
}

func TestCert(t *testing.T) {
	f, err := os.Open("key/testing.ndncert")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	b, err := ioutil.ReadAll(f)
	if err != nil {
		t.Error(err)
	}
	_, err = ReadCertificate(b)
	if err != nil {
		t.Error(err)
	}

	// spew.Dump(cert)
	// GenerateRSAKey()
	// f2, err := os.Create("key/testing.ndncert")
	// if err != nil {
	// 	t.Error(err)
	// }
	// defer f2.Close()
	// b, err = WriteCertificate()
	// if err != nil {
	// 	t.Error(err)
	// }
	// f2.Write(b)

	// f3, err := os.Create("key/testing.pri")
	// if err != nil {
	// 	t.Error(err)
	// }
	// defer f3.Close()
	// b, err = WriteRSAKey()
	// if err != nil {
	// 	t.Error(err)
	// }
	// f3.Write(b)
}
