package ndn

import (
	"io/ioutil"
	"testing"
)

func TestSignKey(t *testing.T) {
	b, err := ioutil.ReadFile("key/testing.pri")
	if err != nil {
		t.Fatal(err)
	}
	err = SignKey.DecodePrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDialRemote(t *testing.T) {
	face, err := NewFace("tcp4", "aleph.ndn.ucla.edu:6363")
	if err != nil {
		t.Fatal(err)
	}
	h := face.Dial(&Interest{
		Name: NewName("/ndn/edu/ucla"),
	})
	select {
	case d := <-h.Data:
		t.Logf("name: %v, sig: %v", d.Name, d.SignatureInfo.KeyLocator.Name)
	case err := <-h.Error:
		t.Fatal(err)
	}
}

func TestDial(t *testing.T) {
	face, err := NewFace("tcp", "localhost:6363")
	if err != nil {
		t.Fatal(err)
	}
	h := face.Dial(&Interest{
		Name: NewName("/localhost/nfd/fib/list"),
		Selectors: Selectors{
			ChildSelector: 1,
			MustBeFresh:   true,
		},
	})
	select {
	case d := <-h.Data:
		t.Logf("name: %v, final block: %v", d.Name, d.MetaInfo.FinalBlockId.Component)
	case err := <-h.Error:
		t.Fatal(err)
	}
}

func TestListen(t *testing.T) {
	face, err := NewFace("tcp", "localhost:6363")
	if err != nil {
		t.Fatal(err)
	}
	h := face.Listen("/hello/world")
	go func() {
		select {
		case i := <-h.Interest:
			t.Logf("producer got %v", i.Name)
			h.Data <- &Data{
				Name: i.Name,
			}
			close(h.Data)
		case err := <-h.Error:
			t.Fatal(err)
		}
	}()
	face2, err := NewFace("tcp", "localhost:6363")
	if err != nil {
		t.Fatal(err)
	}
	h2 := face2.Dial(&Interest{
		Name: NewName("/hello/world"),
	})
	select {
	case d := <-h2.Data:
		t.Logf("consumer got %v", d.Name)
		if d.Name.String() != "/hello/world" {
			t.Fatal("fail to echo")
		}
	case err := <-h2.Error:
		t.Fatal(err)
	}
}
