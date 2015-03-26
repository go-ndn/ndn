package ndn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"testing"

	"github.com/go-ndn/tlv"
)

func BenchmarkDataEncodeRsa(b *testing.B) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	key := Key{PrivateKey: rsaKey}
	packet := &Data{
		Name: NewName("/testing/ndn"),
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := key.Sign(packet)
		if err != nil {
			b.Fatal(err)
		}
		err = packet.WriteTo(ioutil.Discard)
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
	key := Key{PrivateKey: ecdsaKey}
	packet := &Data{
		Name: NewName("/testing/ndn"),
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := key.Sign(packet)
		if err != nil {
			b.Fatal(err)
		}
		err = packet.WriteTo(ioutil.Discard)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDataEncode(b *testing.B) {
	packet := &Data{
		Name: NewName("/testing/ndn"),
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := packet.WriteTo(ioutil.Discard)
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
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := packet.WriteTo(ioutil.Discard)
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
