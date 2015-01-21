package ndn

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
	"testing"
)

func TestConsumer(t *testing.T) {
	conn, err := net.Dial("tcp4", "aleph.ndn.ucla.edu:6363")
	if err != nil {
		t.Fatal(err)
	}
	face := NewFace(conn, nil)
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

func producer(id string) (err error) {
	conn, err := net.Dial("tcp", ":6363")
	if err != nil {
		return
	}
	interestRecv := make(chan *Interest)
	face := NewFace(conn, interestRecv)
	err = face.Register(id)
	if err != nil {
		face.Close()
		return
	}
	d := &Data{
		Name:    NewName(id),
		Content: bytes.Repeat([]byte("0123456789"), 100),
		//MetaInfo: MetaInfo{
		//FreshnessPeriod: 3600000,
		//},
	}
	go func() {
		for _ = range interestRecv {
			face.SendData(d)
		}
		face.Close()
	}()
	return
}

func consumer(id string) (err error) {
	conn, err := net.Dial("tcp", ":6363")
	if err != nil {
		return
	}
	face := NewFace(conn, nil)
	defer face.Close()
	dl, err := face.SendInterest(&Interest{
		Name: NewName(id),
		Selectors: Selectors{
			MustBeFresh: true,
		},
	})
	if err != nil {
		return
	}
	d, ok := <-dl
	if !ok {
		err = fmt.Errorf("timeout %s", face.LocalAddr())
		return
	}
	if d.Name.String() != id {
		err = fmt.Errorf("expected %s, got %s", id, d.Name)
		return
	}
	return
}

func TestProducer(t *testing.T) {
	key, err := ioutil.ReadFile("key/default.pri")
	if err != nil {
		t.Fatal(err)
	}
	err = SignKey.DecodePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("/%x", newNonce())
	err = producer(id)
	if err != nil {
		t.Fatal(err)
	}
	err = consumer(id)
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkBurstyForward(b *testing.B) {
	key, err := ioutil.ReadFile("key/default.pri")
	if err != nil {
		b.Fatal(err)
	}
	err = SignKey.DecodePrivateKey(key)
	if err != nil {
		b.Fatal(err)
	}
	ids := make([]string, 64)
	for i := 0; i < 64; i++ {
		ids[i] = fmt.Sprintf("/%x", newNonce())
	}
	for _, id := range ids {
		err = producer(id)
		if err != nil {
			b.Fatal(err)
		}
	}
	SignKey = Key{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch := make(chan error)
		var wg sync.WaitGroup
		for _, id := range ids {
			wg.Add(1)
			go func(id string) {
				err := consumer(id)
				if err != nil {
					ch <- err
				}
				wg.Done()
			}(id)
		}
		go func() {
			wg.Wait()
			close(ch)
		}()
		for err := range ch {
			b.Error(err)
		}
	}
}

func BenchmarkForwardRTT(b *testing.B) {
	key, err := ioutil.ReadFile("key/default.pri")
	if err != nil {
		b.Fatal(err)
	}
	err = SignKey.DecodePrivateKey(key)
	if err != nil {
		b.Fatal(err)
	}
	id := fmt.Sprintf("/%x", newNonce())
	err = producer(id)
	if err != nil {
		b.Fatal(err)
	}
	SignKey = Key{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := consumer(id)
		if err != nil {
			b.Fatal(err)
		}
	}
}
