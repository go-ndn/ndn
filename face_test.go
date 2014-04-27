package ndn

import (
	//"bytes"
	//"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"testing"
	"time"
)

func TestDial(t *testing.T) {
	face, err := NewFace("tcp://localhost:6363")
	if err != nil {
		t.Error(err)
	}
	d := new(Data)
	err = face.Dial(NewInterest("/localhost/nfd/fib/list"), d)
	if err != nil {
		t.Error(err)
	}
	i2 := new(Interest)
	i2.Name = d.Name
	d2 := new(FibEntryPacket)
	err = face.Dial(i2, d2)
	if err != nil {
		t.Error(err)
	}
	//spew.Dump(d2)
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
	go face.Listen([]string{"/hello/world"}, func(b []byte) ([]byte, error) {
		i := new(Interest)
		err = i.Decode(b)
		if err != nil {
			return nil, err
		}
		d := new(Data)
		d.Name = i.Name
		return d.Encode()
	})
	<-time.After(time.Second)
	face2, err := NewFace("tcp://localhost:6363")
	d := new(Data)
	err = face2.Dial(NewInterest("/hello/world"), d)
	if err != nil {
		t.Error(err)
	}
	//spew.Dump(d)

}
