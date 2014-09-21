package ndn

import (
	"io/ioutil"
	"testing"
)

func TestSignKey(t *testing.T) {
	b, err := ioutil.ReadFile("key/default.pri")
	if err != nil {
		t.Fatal(err)
	}
	err = SignKey.DecodePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDialRemote(t *testing.T) {
	face := &Face{
		Network: "tcp4",
		Address: "aleph.ndn.ucla.edu:6363",
	}
	dl, err := face.Dial(&Interest{
		Name: NewName("/ndn/edu/ucla"),
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := dl.Receive()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("name: %v, sig: %v", d.Name, d.SignatureInfo.KeyLocator.Name)
}

func TestListen(t *testing.T) {
	face := &Face{
		Network: "tcp",
		Address: "localhost:6363",
	}
	ln, err := face.Listen("/hello/world")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			i, err := ln.Accept()
			if err != nil {
				break
			}
			t.Logf("producer got %v", i.Name)
			ln.Send(&Data{Name: i.Name})
		}
	}()
	dl, err := face.Dial(&Interest{
		Name: NewName("/hello/world"),
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := dl.Receive()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("consumer got %v", d.Name)
	if d.Name.String() != "/hello/world" {
		t.Fatal("fail to echo")
	}
}
