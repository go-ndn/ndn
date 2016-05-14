package ndn

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-ndn/packet"
)

type testFace struct {
	Face
	recv <-chan *Interest
}

func newTestFace(address string) (f *testFace, err error) {
	conn, err := packet.Dial("tcp", address)
	if err != nil {
		return
	}
	recv := make(chan *Interest)
	f = &testFace{
		Face: NewFace(conn, recv),
		recv: recv,
	}
	return
}

func (f *testFace) produce(name string) (err error) {
	err = SendControl(f, "rib", "register", &Parameters{
		Name: NewName(name),
	}, rsaKey)
	if err != nil {
		return
	}
	d := &Data{
		Name:    NewName(name),
		Content: bytes.Repeat([]byte("0123456789"), 100),
	}
	go func() {
		for range f.recv {
			f.SendData(d)
		}
	}()
	return
}

func (f *testFace) consume(name string) (err error) {
	_, ok := <-f.SendInterest(&Interest{
		Name: NewName(name),
		/*
			Selectors: Selectors{
				MustBeFresh: true,
			},
		*/
	})
	if !ok {
		err = ErrTimeout
		return
	}
	return
}

func TestConsumer(t *testing.T) {
	consumer, err := newTestFace("spurs.cs.ucla.edu:6363")
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	err = consumer.consume("/ndn/edu/ucla/ping")
	if err != nil {
		t.Fatal(err)
	}
}

func TestProducer(t *testing.T) {
	name := fmt.Sprintf("/%x", newNonce())
	producer, err := newTestFace(":6363")
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	err = producer.produce(name)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	consumer, err := newTestFace(":6363")
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	err = consumer.consume(name)
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkBurstyForward(b *testing.B) {
	names := make([]string, 64)
	consumers := make([]*testFace, len(names))
	for i := 0; i < len(names); i++ {
		names[i] = fmt.Sprintf("/%x", newNonce())
		// producer
		producer, err := newTestFace(":6363")
		if err != nil {
			b.Fatal(err)
		}
		defer producer.Close()
		err = producer.produce(names[i])
		if err != nil {
			b.Fatal(err)
		}
		// consumer
		consumers[i], err = newTestFace(":6363")
		if err != nil {
			b.Fatal(err)
		}
		defer consumers[i].Close()
	}
	time.Sleep(time.Second)
	b.ResetTimer()

	ch := make(chan error, 1)
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		wg.Add(len(names))
		for j := range names {
			go func(j int) {
				err := consumers[j].consume(names[j])
				if err != nil {
					select {
					case ch <- err:
					default:
					}
				}
				wg.Done()
			}(j)
		}
		wg.Wait()
	}
	select {
	case err := <-ch:
		b.Error(err)
	default:
	}
}

func BenchmarkForwardRTT(b *testing.B) {
	name := fmt.Sprintf("/%x", newNonce())
	// producer
	producer, err := newTestFace(":6363")
	if err != nil {
		b.Fatal(err)
	}
	defer producer.Close()
	err = producer.produce(name)
	if err != nil {
		b.Fatal(err)
	}
	// consumer
	consumer, err := newTestFace(":6363")
	if err != nil {
		b.Fatal(err)
	}
	defer consumer.Close()
	time.Sleep(time.Second)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := consumer.consume(name)
		if err != nil {
			b.Fatal(err)
		}
	}
}
