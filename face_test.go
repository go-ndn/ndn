package ndn

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNewFace(t *testing.T) {
	face := NewFace("borges.metwi.ucla.edu")
	if face.Scheme != "tcp" {
		t.Errorf("expected %v, got %v", "tcp", face.Scheme)
	}
	if face.Host != "borges.metwi.ucla.edu:6363" {
		t.Errorf("expected %v, got %v", "borges.metwi.ucla.edu:6363", face.Host)
	}

	face2 := NewFace("udp://example.com")
	if face2.Scheme != "udp" {
		t.Errorf("expected %v, got %v", "udp", face2.Scheme)
	}
	face3 := NewFace("udp://example.com:4000")
	if !strings.HasSuffix(face3.Host, ":4000") {
		t.Errorf("expected %v, got %v", ":4000", face3)
	}
}

func TestDial(t *testing.T) {
	face := NewFace("borges.metwi.ucla.edu")
	i := NewInterest("/ndnx/ping")
	d, err := face.Dial(i)
	if err != nil {
		if err.Error() != "dial tcp: lookup borges.metwi.ucla.edu: no such host" {
			t.Error(err)
		}
	} else {
		if len(d.Name) != 2 || !bytes.Equal(d.Name[0], []byte("ndnx")) || !bytes.Equal(d.Name[1], []byte("ping")) {
			t.Errorf("expected %v, got %v", i.Name, d.Name)
		}
	}
}

func TestListen(t *testing.T) {
	GenerateRSAKey()
	face := NewFace("127.0.0.1")
	face.Listen("/ping", func(i *Interest) *Data {
		return NewData("/pong")
	})
	face.Listen("/happy/day", func(i *Interest) *Data {
		return NewData("/cheer")
	})
	go face.Run()
	<-time.After(time.Nanosecond)
	i := NewInterest("/ping")
	d, err := NewFace("127.0.0.1").Dial(i)
	if err != nil {
		t.Error(err)
	} else {
		if len(d.Name) != 1 || !bytes.Equal(d.Name[0], []byte("pong")) {
			t.Errorf("expected %v, got %v", i.Name, d.Name)
		}
	}
	i2 := NewInterest("/happy/day")
	d2, err := NewFace("127.0.0.1").Dial(i2)
	if err != nil {
		t.Error(err)
	} else {
		if len(d2.Name) != 1 || !bytes.Equal(d2.Name[0], []byte("cheer")) {
			t.Errorf("expected %v, got %v", i2.Name, d2.Name)
		}
	}
}
