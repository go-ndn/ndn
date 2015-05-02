package ndn

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func producer(name string) (err error) {
	conn, err := net.Dial("tcp", ":6363")
	if err != nil {
		return
	}
	recv := make(chan *Interest)
	f := NewFace(conn, recv)
	err = SendControl(f, "rib", "register", &Parameters{
		Name: NewName(name),
	}, &rsaKey)
	if err != nil {
		f.Close()
		return
	}
	d := &Data{
		Name: NewName(name),
		MetaInfo: MetaInfo{
			FreshnessPeriod: 4000,
		},
		Content: bytes.Repeat([]byte("0123456789"), 100),
	}
	go func() {
		for _ = range recv {
			f.SendData(d)
		}
		f.Close()
	}()
	return
}

func consumer(name string) (err error) {
	conn, err := net.Dial("tcp", ":6363")
	if err != nil {
		return
	}
	f := NewFace(conn, nil)
	defer f.Close()
	d, ok := <-f.SendInterest(&Interest{
		Name: NewName(name),
		Selectors: Selectors{
			MustBeFresh: true,
		},
	})
	if !ok {
		err = ErrTimeout
		return
	}
	if d.Name.String() != name {
		err = errors.New(name)
		return
	}
	return
}

func TestConsumer(t *testing.T) {
	conn, err := net.Dial("tcp4", "spurs.cs.ucla.edu:6363")
	if err != nil {
		t.Fatal(err)
	}
	f := NewFace(conn, nil)
	defer f.Close()
	d, ok := <-f.SendInterest(&Interest{
		Name: NewName("/ndn/edu/ucla/ping"),
	})
	if !ok {
		t.Fatal("timeout")
	}
	t.Logf("name: %s, key: %s", d.Name, d.SignatureInfo.KeyLocator.Name)
}

func TestProducer(t *testing.T) {
	name := fmt.Sprintf("/%x", newNonce())
	err := producer(name)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	err = consumer(name)
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkBurstyForward(b *testing.B) {
	names := make([]string, 64)
	for i := 0; i < len(names); i++ {
		names[i] = fmt.Sprintf("/%x", newNonce())
	}
	for _, name := range names {
		err := producer(name)
		if err != nil {
			b.Fatal(err)
		}
	}
	time.Sleep(time.Second)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ch := make(chan error)
		var wg sync.WaitGroup
		wg.Add(len(names))
		for _, name := range names {
			go func(name string) {
				err := consumer(name)
				if err != nil {
					ch <- err
				}
				wg.Done()
			}(name)
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
	name := fmt.Sprintf("/%x", newNonce())
	err := producer(name)
	if err != nil {
		b.Fatal(err)
	}
	time.Sleep(time.Second)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := consumer(name)
		if err != nil {
			b.Fatal(err)
		}
	}
}
