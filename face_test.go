package ndn

import (
	//"bytes"
	"io/ioutil"
	"testing"
)

func TestDial(t *testing.T) {
	b, err := ioutil.ReadFile("key/testing.pri")
	if err != nil {
		t.Error(err)
		return
	}
	err = SignKey.Decode(b)
	if err != nil {
		t.Error(err)
		return
	}
	face, err := NewFace("tcp://localhost:6363")
	if err != nil {
		t.Error(err)
		return
	}
	d := new(Data)
	err = face.Dial(NewInterest("/localhost/nfd/fib/list"), d)
	if err != nil {
		t.Error(err)
		return
	}
	i2 := new(Interest)
	i2.Name = d.Name
	d2 := new(FibEntryPacket)
	err = face.Dial(i2, d2)
	if err != nil {
		t.Error(err)
		return
	}
	Print(d2)
}

func TestListen(t *testing.T) {
	b, err := ioutil.ReadFile("key/testing.pri")
	if err != nil {
		t.Error(err)
		return
	}
	err = SignKey.Decode(b)
	if err != nil {
		t.Error(err)
		return
	}

	face, err := NewFace("tcp://localhost:6363")
	if err != nil {
		t.Error(err)
		return
	}
	err = face.Announce("/hello/world")
	go face.Listen(func() ReadFrom { return new(Interest) }, func(r ReadFrom) (w WriteTo, err error) {
		i, _ := r.(*Interest)
		w = NewData(i.Name.String())
		return
	})
	face2, err := NewFace("tcp://localhost:6363")
	d := new(Data)
	err = face2.Dial(NewInterest("/hello/world"), d)
	if err != nil {
		t.Error(err)
	}
	Print(d)
}
