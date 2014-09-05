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

func TestListen(t *testing.T) {
	face, err := NewFace()
	if err != nil {
		t.Fatal(err)
	}
	err = face.Announce("/hello/world")
	if err != nil {
		t.Fatal(err)
	}
	go face.Listen(func(i *Interest) (*Data, error) {
		return NewData(i.Name.String()), nil
	})
	face2, err := NewFace()
	if err != nil {
		t.Fatal(err)
	}
	d, err := face2.Dial(NewInterest("/hello/world"))
	if err != nil {
		t.Fatal(err)
	}
	if d.Name.String() != "/hello/world" {
		t.Fatal("fail to echo")
	}
}
