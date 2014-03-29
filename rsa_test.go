package ndn

import (
	"bytes"
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
