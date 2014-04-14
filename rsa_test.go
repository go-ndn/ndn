package ndn

import (
	"bytes"
	//"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"os"
	"testing"
)

func TestRSA(t *testing.T) {
	key, err := NewKey("")
	if err != nil {
		t.Error(err)
		return
	}
	b := key.Encode()
	key2 := Key{}
	err = key2.Decode(b)
	if err != nil {
		t.Error(err)
		return
	}
	b2 := key2.Encode()
	if !bytes.Equal(b, b2) {
		t.Error("RSA key should be the same")
		return
	}
}

func TestCert(t *testing.T) {
	f, err := os.Open("key/testing.ndncert")
	if err != nil {
		t.Error(err)
		return
	}
	defer f.Close()
	b, err := ioutil.ReadAll(f)
	if err != nil {
		t.Error(err)
		return
	}
	err = PrintCertificate(b)
	if err != nil {
		t.Error(err)
		return
	}
}
