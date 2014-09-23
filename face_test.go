package ndn

import (
	"io/ioutil"
	"net"
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
	conn, err := net.Dial("tcp4", "aleph.ndn.ucla.edu:6363")
	if err != nil {
		t.Fatal(err)
	}
	face := NewFace(conn)
	defer face.Close()
	dl, err := face.SendInterest(&Interest{
		Name: NewName("/ndn/edu/ucla"),
	})
	if err != nil {
		t.Fatal(err)
	}
	d, ok := <-dl
	if !ok {
		t.Fatal("timeout")
	}
	t.Logf("name: %v, sig: %v", d.Name, d.SignatureInfo.KeyLocator.Name)
}

func TestListen(t *testing.T) {
	conn, err := net.Dial("tcp", "localhost:6363")
	if err != nil {
		t.Fatal(err)
	}
	face := NewFace(conn)
	defer face.Close()
	err = face.AddNextHop("/hello/world", 1)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for i := range face.InterestIn {
			t.Logf("producer got %v", i.Name)
			face.SendData(&Data{Name: i.Name})
		}
	}()
	conn2, err := net.Dial("tcp", "localhost:6363")
	if err != nil {
		t.Fatal(err)
	}
	face2 := NewFace(conn2)
	defer face2.Close()
	dl, err := face2.SendInterest(&Interest{
		Name: NewName("/hello/world"),
	})
	if err != nil {
		t.Fatal(err)
	}
	d, ok := <-dl
	if !ok {
		t.Fatal("timeout")
	}
	t.Logf("consumer got %v", d.Name)
	if d.Name.String() != "/hello/world" {
		t.Fatal("fail to echo")
	}
}
