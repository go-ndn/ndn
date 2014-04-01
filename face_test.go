package ndn

import (
	"bytes"
	//"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewFace(t *testing.T) {
	face := NewFace("borges.metwi.ucla.edu")
	if face.Scheme != "tcp" {
		t.Errorf("expected %v, got %v", "tcp", face.Scheme)
		return
	}
	if face.Host != "borges.metwi.ucla.edu:6363" {
		t.Errorf("expected %v, got %v", "borges.metwi.ucla.edu:6363", face.Host)
		return
	}

	face2 := NewFace("udp://example.com")
	if face2.Scheme != "udp" {
		t.Errorf("expected %v, got %v", "udp", face2.Scheme)
		return
	}
	face3 := NewFace("udp://example.com:4000")
	if !strings.HasSuffix(face3.Host, ":4000") {
		t.Errorf("expected %v, got %v", ":4000", face3)
		return
	}
}

func TestDial(t *testing.T) {
	face := NewFace("borges.metwi.ucla.edu")
	i := NewInterest("/ndnx/ping")
	d, err := face.Dial(i)
	if err != nil {
		return
	}

	if len(d.Name) != 2 || !bytes.Equal(d.Name[0], []byte("ndnx")) || !bytes.Equal(d.Name[1], []byte("ping")) {
		t.Errorf("expected %v, got %v", i.Name, d.Name)
		return
	}
}

func TestListen(t *testing.T) {
	f, err := os.Open("key/testing.pri")
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
	err = ReadRSAKey(b)
	if err != nil {
		t.Error(err)
		return
	}
	face := NewFace("127.0.0.1")
	face.On("/test", func(i *Interest) *Data {
		//fmt.Println("got Interest")
		return NewData("/test")
	})
	go face.Listen()
	<-time.After(3 * time.Second)
	d, err := face.Dial(NewInterest("/test"))
	if err != nil {
		t.Error(err)
		return
	}
	if nameToString(d.Name) != "/test" {
		t.Errorf("expected %v, got %v", "/test", nameToString(d.Name))
		return
	}
}
