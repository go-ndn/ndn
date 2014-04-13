package ndn

import (
	"bytes"
	//"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestNewFace(t *testing.T) {
	face, err := NewFace("borges.metwi.ucla.edu")
	if err == nil {
		t.Errorf("should not be valid face name %#v", face)
		return
	}

	_, err = NewFace("udp://example.com:6363")
	if err != nil {
		t.Error(err)
		return
	}
}

func TestDial(t *testing.T) {
	face, err := NewFace("tcp://borges.metwi.ucla.edu:6363")
	if err != nil {
		t.Error(err)
		return
	}
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
	key, err = ReadRSAKey(b)
	if err != nil {
		t.Error(err)
		return
	}
	SignKey = key
	VerifyKey = key
	face, err := NewFace("tcp://127.0.0.1:6363")
	if err != nil {
		t.Error(err)
		return
	}
	face.On("/test", func(i *Interest, d *Data) error {
		//fmt.Println("got Interest")
		d.Name = [][]byte{[]byte("test")}
		return nil
	})
	go face.Listen()
	<-time.After(time.Second)
	d, err := face.Dial(NewInterest("/test"))
	if err != nil {
		return
	}
	if nameToString(d.Name) != "/test" {
		t.Errorf("expected %v, got %v", "/test", nameToString(d.Name))
		return
	}
}
