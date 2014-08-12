package ndn

import (
	"bytes"
	"testing"
	"bufio"
)

func BenchmarkDataEncodeRsa(b *testing.B) {
	b.StopTimer()
	packet := NewData("/testing/ndn")
	packet.SignatureInfo.SignatureType = SignatureTypeSha256WithRsa
	buf := new(bytes.Buffer)
	b.StartTimer()
    for i := 0; i < b.N; i++ {
    	err := packet.WriteTo(buf)
    	if err != nil {
    		b.Fatal(err)
    	}
    }
}

func BenchmarkDataEncodeEcdsa(b *testing.B) {
	b.StopTimer()
	packet := NewData("/testing/ndn")
	packet.SignatureInfo.SignatureType = SignatureTypeSha256WithEcdsa
	buf := new(bytes.Buffer)
	b.StartTimer()
    for i := 0; i < b.N; i++ {
    	err := packet.WriteTo(buf)
    	if err != nil {
    		b.Fatal(err)
    	}
    }
}

func BenchmarkDataEncode(b *testing.B) {
	b.StopTimer()
	packet := NewData("/testing/ndn")
	buf := new(bytes.Buffer)
	b.StartTimer()
    for i := 0; i < b.N; i++ {
    	err := packet.WriteTo(buf)
    	if err != nil {
    		b.Fatal(err)
    	}
    }
}

func BenchmarkDataDecode(b *testing.B) {
	b.StopTimer()
	packet := NewData("/testing/ndn")
	buf := new(bytes.Buffer)
    for i := 0; i < b.N; i++ {
    	packet.WriteTo(buf)
    	b.StartTimer()
    	err := new(Data).ReadFrom(bufio.NewReader(buf))
    	if err != nil {
    		b.Fatal(err)
    	}
    	b.StopTimer()
    }
}

func BenchmarkInterestEncode(b *testing.B) {
	b.StopTimer()
	packet := NewInterest("/testing/ndn")
	buf := new(bytes.Buffer)
	b.StartTimer()
    for i := 0; i < b.N; i++ {
    	err := packet.WriteTo(buf)
    	if err != nil {
    		b.Fatal(err)
    	}
    }
}

func BenchmarkInterestDecode(b *testing.B) {
	b.StopTimer()
	packet := NewInterest("/testing/ndn")
	buf := new(bytes.Buffer)
    for i := 0; i < b.N; i++ {
    	packet.WriteTo(buf)
    	b.StartTimer()
    	err := new(Interest).ReadFrom(bufio.NewReader(buf))
    	if err != nil {
    		b.Fatal(err)
    	}
    	b.StopTimer()
    }
}