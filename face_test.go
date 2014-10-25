package ndn

import (
	"bytes"
	"encoding/hex"
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

func producer() (err error) {
	conn, err := net.Dial("tcp", ":6363")
	if err != nil {
		return
	}
	interestIn := make(chan *Interest)
	face := NewFace(conn, interestIn)
	err = face.Register("/test")
	if err != nil {
		face.Close()
		return
	}
	content := bytes.Repeat([]byte("0123456789"), 100)
	go func() {
		for i := range interestIn {
			face.SendData(&Data{
				Name:    i.Name,
				Content: content,
			})
		}
		face.Close()
	}()
	return
}

func consumer(ch chan<- error) {
	conn, err := net.Dial("tcp", ":6363")
	if err != nil {
		ch <- err
		return
	}
	face := NewFace(conn, nil)
	defer face.Close()
	rand := hex.EncodeToString(newNonce())
	dl, err := face.SendInterest(&Interest{
		Name: NewName("/test/" + rand),
	})
	if err != nil {
		ch <- err
		return
	}
	d, ok := <-dl
	if !ok {
		ch <- fmt.Errorf("timeout %s", face.LocalAddr())
		return
	}
	if d.Name.String() != "/test/"+rand {
		ch <- fmt.Errorf("fail to echo %s %s", rand, d.Name)
		return
	}
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

	err = producer()
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan error)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			consumer(ch)
			wg.Done()
		}()
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	for err := range ch {
		t.Error(err)
	}
}

func BenchmarkForward(b *testing.B) {
	key, err := ioutil.ReadFile("key/default.pri")
	if err != nil {
		b.Fatal(err)
	}
	err = SignKey.DecodePrivateKey(key)
	if err != nil {
		b.Fatal(err)
	}

	err = producer()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ch := make(chan error)
		var wg sync.WaitGroup
		for i := 0; i < 256; i++ {
			wg.Add(1)
			go func() {
				consumer(ch)
				wg.Done()
			}()
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
