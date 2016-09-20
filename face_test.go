package ndn

import (
	"bytes"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/go-ndn/packet"
)

type testFace struct {
	Face
}

func newTestFace(address string) (*testFace, error) {
	conn, err := packet.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	return &testFace{
		Face: NewFace(conn, nil),
	}, nil
}

func (f *testFace) consume(name string) error {
	_, ok := <-f.SendInterest(&Interest{
		Name: NewName(name),
	})
	if !ok {
		return ErrTimeout
	}
	return nil
}

func newProducer(address, name string) (Face, error) {
	conn, err := packet.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	recv := make(chan *Interest)
	f := NewFace(conn, recv)
	err = SendControl(f, "rib", "register", &Parameters{
		Name: NewName(name),
	}, rsaKey)
	if err != nil {
		return nil, err
	}
	go func() {
		d := &Data{
			Name:    NewName(name),
			Content: bytes.Repeat([]byte("0123456789"), 100),
			SignatureInfo: SignatureInfo{
				SignatureType: SignatureTypeDigestCRC32C,
			},
		}
		for range recv {
			f.SendData(d)
		}
	}()
	return f, nil
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

func TestConsumerTimeout(t *testing.T) {
	consumer, err := newTestFace("spurs.cs.ucla.edu:6363")
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	_, ok := <-consumer.SendInterest(&Interest{
		Name:     NewName("/ndn/edu/ucla/ping"),
		LifeTime: 1,
	})
	if ok {
		t.Fatalf("expect closed data channel")
	}
}

func TestProducer(t *testing.T) {
	name := fmt.Sprintf("/%x", rand.Uint32())
	producer, err := newProducer(":6363", name)
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
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
		names[i] = fmt.Sprintf("/%x", rand.Uint32())
		// producer
		producer, err := newProducer(":6363", names[i])
		if err != nil {
			b.Fatal(err)
		}
		defer producer.Close()
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
	name := fmt.Sprintf("/%x", rand.Uint32())
	// producer
	producer, err := newProducer(":6363", name)
	if err != nil {
		b.Fatal(err)
	}
	defer producer.Close()
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
