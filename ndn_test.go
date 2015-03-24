package ndn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-ndn/tlv"
)

func BenchmarkDataEncodeRsa(b *testing.B) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	SignKey = Key{PrivateKey: rsaKey}

	buf := new(bytes.Buffer)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := &Data{
			Name: NewName("/testing/ndn"),
		}
		packet.SignatureInfo.SignatureType = SignatureTypeSha256WithRsa
		err := packet.WriteTo(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDataEncodeEcdsa(b *testing.B) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	SignKey = Key{PrivateKey: ecdsaKey}

	buf := new(bytes.Buffer)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := &Data{
			Name: NewName("/testing/ndn"),
		}
		packet.SignatureInfo.SignatureType = SignatureTypeSha256WithEcdsa
		err := packet.WriteTo(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDataEncode(b *testing.B) {
	packet := &Data{
		Name: NewName("/testing/ndn"),
	}
	buf := new(bytes.Buffer)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := packet.WriteTo(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDataDecode(b *testing.B) {
	packet := &Data{
		Name: NewName("/testing/ndn"),
	}
	buf := new(bytes.Buffer)
	packet.WriteTo(buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := new(Data).ReadFrom(tlv.NewReader(bytes.NewReader(buf.Bytes())))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInterestEncode(b *testing.B) {
	packet := &Interest{
		Name: NewName("/testing/ndn"),
	}
	buf := new(bytes.Buffer)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := packet.WriteTo(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInterestDecode(b *testing.B) {
	packet := &Interest{
		Name: NewName("/testing/ndn"),
	}
	buf := new(bytes.Buffer)
	packet.WriteTo(buf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := new(Interest).ReadFrom(tlv.NewReader(bytes.NewReader(buf.Bytes())))
		if err != nil {
			b.Fatal(err)
		}
	}
}
