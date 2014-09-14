package ndn

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func BenchmarkDataEncodeRsa(b *testing.B) {
	b.StopTimer()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	SignKey = Key{
		Name:       NewName("/testing/key"),
		PrivateKey: rsaKey,
	}

	packet := &Data{
		Name: NewName("/testing/ndn"),
	}
	packet.SignatureInfo.SignatureType = SignatureTypeSha256WithRsa
	buf := new(bytes.Buffer)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		err := packet.writeTo(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDataEncodeEcdsa(b *testing.B) {
	b.StopTimer()
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	SignKey = Key{
		Name:       NewName("/testing/key"),
		PrivateKey: ecdsaKey,
	}

	packet := &Data{
		Name: NewName("/testing/ndn"),
	}
	packet.SignatureInfo.SignatureType = SignatureTypeSha256WithEcdsa
	buf := new(bytes.Buffer)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		err := packet.writeTo(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDataEncode(b *testing.B) {
	b.StopTimer()
	packet := &Data{
		Name: NewName("/testing/ndn"),
	}
	buf := new(bytes.Buffer)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		err := packet.writeTo(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDataDecode(b *testing.B) {
	b.StopTimer()
	packet := &Data{
		Name: NewName("/testing/ndn"),
	}
	buf := new(bytes.Buffer)
	for i := 0; i < b.N; i++ {
		packet.writeTo(buf)
		b.StartTimer()
		err := new(Data).readFrom(bufio.NewReader(buf))
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
	}
}

func BenchmarkInterestEncode(b *testing.B) {
	b.StopTimer()
	packet := &Interest{
		Name: NewName("/testing/ndn"),
	}
	buf := new(bytes.Buffer)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		err := packet.writeTo(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInterestDecode(b *testing.B) {
	b.StopTimer()
	packet := &Interest{
		Name: NewName("/testing/ndn"),
	}
	buf := new(bytes.Buffer)
	for i := 0; i < b.N; i++ {
		packet.writeTo(buf)
		b.StartTimer()
		err := new(Interest).readFrom(bufio.NewReader(buf))
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
	}
}
