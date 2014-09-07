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

func TestDialRemote(t *testing.T) {
	face, err := NewFace("tcp4", "aleph.ndn.ucla.edu:6363")
	if err != nil {
		t.Fatal(err)
	}
	dc := face.Dial(&Interest{
		Name: NewName("/ndn/edu/ucla"),
	})
	t.Logf("[names]")
	for d := range dc {
		t.Logf("name: %v, sig: %v", d.Name, d.SignatureInfo.KeyLocator.Name)
	}
}

func TestDial(t *testing.T) {
	face, err := NewFace("tcp", "localhost:6363")
	if err != nil {
		t.Fatal(err)
	}
	dc := face.Dial(&Interest{
		Name: NewName("/localhost/nfd/fib/list"),
		Selectors: Selectors{
			ChildSelector: 1,
			MustBeFresh:   true,
		},
	})
	t.Logf("[names]")
	for d := range dc {
		t.Logf("name: %v, final block: %v", d.Name, d.MetaInfo.FinalBlockId.Component)
	}
}

func TestListen(t *testing.T) {
	face, err := NewFace("tcp", "localhost:6363")
	if err != nil {
		t.Fatal(err)
	}
	ic, dc := face.Listen("/hello/world")
	go func() {
		for i := range ic {
			t.Logf("producer got %v", i.Name)
			dc <- &Data{
				Name: i.Name,
			}
		}
	}()
	face2, err := NewFace("tcp", "localhost:6363")
	if err != nil {
		t.Fatal(err)
	}
	echo := face2.Dial(&Interest{
		Name: NewName("/hello/world"),
	})
	for d := range echo {
		t.Logf("consumer got %v", d.Name)
		if d.Name.String() != "/hello/world" {
			t.Fatal("fail to echo")
		}
	}
}
