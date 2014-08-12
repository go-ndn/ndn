package ndn

import (
	//"bytes"
	"io/ioutil"
	"testing"
)

func TestSignKey(t *testing.T) {
	b, err := ioutil.ReadFile("key/testing.pri")
	if err != nil {
		t.Fatal(err)
	}
	err = SignKey.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDial(t *testing.T) {
	face, err := NewFace("tcp://localhost:6363")
	if err != nil {
		t.Fatal(err)
	}
	d := new(Data)
	err = face.Dial(NewInterest("/localhost/nfd/fib/list"), d)
	if err != nil {
		t.Fatal(err)
	}
	i2 := NewInterest(d.Name.String())
	d2 := new(FibEntryPacket)
	err = face.Dial(i2, d2)
	if err != nil {
		t.Fatal(err)
	}
}

func TestListen(t *testing.T) {
	face, err := NewFace("tcp://localhost:6363")
	if err != nil {
		t.Fatal(err)
	}
	err = face.Announce("/hello/world")
	if err != nil {
		t.Fatal(err)
	}
	go face.Listen(AcceptInterest, func(r ReadFrom) (WriteTo, error) {
		i, _ := r.(*Interest)
		return NewData(i.Name.String()), nil
	})
	face2, err := NewFace("tcp://localhost:6363")
	if err != nil {
		t.Fatal(err)
	}
	d := new(Data)
	err = face2.Dial(NewInterest("/hello/world"), d)
	if err != nil {
		t.Fatal(err)
	}
}
