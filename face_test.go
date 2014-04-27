package ndn

import (
	//"bytes"
	"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"testing"
	"time"
)

func TestDial(t *testing.T) {
	face, err := NewFace("tcp://localhost:6363")
	if err != nil {
		t.Error(err)
	}
	d := new(ForwarderStatusPacket)
	err = face.Dial(NewInterest("/localhost/nfd/status"), d)
	if err != nil {
		t.Error(err)
	}
	//spew.Dump(d)
}

func TestListen(t *testing.T) {
	b, err := ioutil.ReadFile("key/testing.pri")
	if err != nil {
		t.Error(err)
		return
	}
	SignKey.Decode(b)
	if err != nil {
		t.Error(err)
		return
	}

	face, err := NewFace("tcp://localhost:6363")
	face.On("/hello/world", func(b []byte) ([]byte, error) {
		i := new(Interest)
		err = i.Decode(b)
		if err != nil {
			return nil, err
		}
		d := new(Data)
		d.Name = i.Name
		return d.Encode()
	})
	go face.Listen()
	<-time.After(time.Second)
	face2, err := NewFace("tcp://localhost:6363")
	d := new(Data)
	err = face2.Dial(NewInterest("/hello/world"), d)
	if err != nil {
		t.Error(err)
	}
	spew.Dump(d)

}
