package ndn

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/go-ndn/tlv"
)

func BenchmarkDataEncodeRsa(b *testing.B) {
	packet := new(Data)
	for i := 0; i < b.N; i++ {
		err := rsaKey.Sign(packet)
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
	packet := new(Data)
	for i := 0; i < b.N; i++ {
		err := ecdsaKey.Sign(packet)
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
	packet := new(Data)
	for i := 0; i < b.N; i++ {
		err := packet.WriteTo(ioutil.Discard)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDataDecode(b *testing.B) {
	packet := new(Data)
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
	packet := new(Interest)
	for i := 0; i < b.N; i++ {
		err := packet.WriteTo(ioutil.Discard)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInterestDecode(b *testing.B) {
	packet := new(Interest)
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
