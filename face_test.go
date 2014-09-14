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
	h, err := face.Dial(&Interest{
		Name: NewName("/ndn/edu/ucla"),
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-h.Data:
		t.Logf("name: %v, sig: %v", d.Name, d.SignatureInfo.KeyLocator.Name)
	case err := <-h.Error:
		t.Fatal(err)
	}
}

func TestDial(t *testing.T) {
	face := &Face{
		Network: "tcp",
		Address: "localhost:6363",
	}
	h, err := face.Dial(&Interest{
		Name: NewName("/localhost/nfd/fib/list"),
		Selectors: Selectors{
			ChildSelector: 1,
			MustBeFresh:   true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-h.Data:
		t.Logf("name: %v, final block: %v", d.Name, d.MetaInfo.FinalBlockId.Component)
	case err := <-h.Error:
		t.Fatal(err)
	}
}

func TestListen(t *testing.T) {
	face := &Face{
		Network: "tcp",
		Address: "localhost:6363",
	}
	h, err := face.Listen("/hello/world")
	if err != nil {
		t.Fatal(err)
	}
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
	face2 := &Face{
		Network: "tcp",
		Address: "localhost:6363",
	}
	h2, err := face2.Dial(&Interest{
		Name: NewName("/hello/world"),
	})
	if err != nil {
		t.Fatal(err)
	}
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
