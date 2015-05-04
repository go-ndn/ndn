package ndn

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/go-ndn/tlv"
)

var (
	interest = &Interest{Name: NewName("/hello")}
	data     = &Data{Name: NewName("/hello")}
)

func BenchmarkDataEncodeRSA(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := rsaKey.SignData(data)
		if err != nil {
			b.Fatal(err)
		}
		err = data.WriteTo(ioutil.Discard)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDataEncodeECDSA(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := ecdsaKey.SignData(data)
		if err != nil {
			b.Fatal(err)
		}
		err = data.WriteTo(ioutil.Discard)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDataEncode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := data.WriteTo(ioutil.Discard)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDataDecode(b *testing.B) {
	buf := new(bytes.Buffer)
	data.WriteTo(buf)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := new(Data).ReadFrom(tlv.NewReader(bytes.NewReader(buf.Bytes())))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInterestEncode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := interest.WriteTo(ioutil.Discard)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInterestDecode(b *testing.B) {
	buf := new(bytes.Buffer)
	interest.WriteTo(buf)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := new(Interest).ReadFrom(tlv.NewReader(bytes.NewReader(buf.Bytes())))
		if err != nil {
			b.Fatal(err)
		}
	}
}
