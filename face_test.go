package ndn

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
	"testing"
)

var (
	errUnexpectedData = errors.New("unexpected data")
)

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
	ch, err := face.SendInterest(&Interest{
		Name: NewName(id),
		Selectors: Selectors{
			MustBeFresh: true,
		},
	})
	if err != nil {
		return
	}
	d, ok := <-ch
	if !ok {
		err = ErrTimeout
		return
	}
	if d.Name.String() != id {
		err = errUnexpectedData
		return
	}
	return
}

func TestConsumer(t *testing.T) {
	conn, err := net.Dial("tcp4", "spurs.cs.ucla.edu:6363")
	if err != nil {
		t.Fatal(err)
	}
	face := NewFace(conn, nil)
	defer face.Close()
	ch, err := face.SendInterest(&Interest{
		Name: NewName("/ndn/edu/ucla"),
	})
	if err != nil {
		t.Fatal(err)
	}
	d, ok := <-ch
	if !ok {
		t.Fatal("timeout")
	}
	t.Logf("name: %s, sig: %s", d.Name, d.SignatureInfo.KeyLocator.Name)
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
