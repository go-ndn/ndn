package ndn

import (
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/go-ndn/lpm"
	"github.com/go-ndn/tlv"
)

// Sender sends interest and data packets.
// This is the minimum abstraction for NDN nodes.
type Sender interface {
	SendInterest(*Interest) <-chan *Data
	SendData(*Data)
}

// Face implements Sender.
type Face interface {
	Sender
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}

type face struct {
	net.Conn
	tlv.Reader // read

	tlv.Writer            // write
	wm         sync.Mutex // writer mutex

	pitMatcher            // pit
	pitm       sync.Mutex // pit mutex

	recv chan<- *Interest
}

type pitEntry struct {
	*Selectors
	timer *time.Timer
}

// NewFace creates a face from net.Conn.
//
// recv is the incoming interest queue.
// If it is nil, incoming interests will be ignored.
// Otherwise, this queue must be handled before it is full.
func NewFace(transport net.Conn, recv chan<- *Interest) Face {
	f := &face{
		Conn:   transport,
		Reader: tlv.NewReader(transport),
		Writer: tlv.NewWriter(transport),
		recv:   recv,
	}
	go func() {
		for {
			switch f.Peek() {
			case 5:
				i := new(Interest)
				err := i.ReadFrom(f.Reader)
				if err != nil {
					goto IDLE
				}
				f.recvInterest(i)
			case 6:
				d := new(Data)
				err := d.ReadFrom(f.Reader)
				if err != nil {
					goto IDLE
				}
				f.recvData(d)
			default:
				goto IDLE
			}
		}
	IDLE:
		if f.recv != nil {
			close(f.recv)
		}
	}()
	return f
}

func (f *face) SendData(d *Data) {
	f.wm.Lock()
	d.WriteTo(f.Writer)
	f.wm.Unlock()
}

func (f *face) SendInterest(i *Interest) <-chan *Data {
	ch := make(chan *Data, 1)

	lifeTime := 4 * time.Second
	if i.LifeTime != 0 {
		lifeTime = time.Duration(i.LifeTime) * time.Millisecond
	}
	timer := time.AfterFunc(lifeTime, func() {
		f.pitm.Lock()
		f.Update(i.Name.Components, func(m map[chan<- *Data]pitEntry) map[chan<- *Data]pitEntry {
			if m == nil {
				return nil
			}
			if _, ok := m[ch]; !ok {
				return m
			}
			close(ch)
			delete(m, ch)
			if len(m) == 0 {
				return nil
			}
			return m
		}, false)
		f.pitm.Unlock()
	})

	f.pitm.Lock()
	f.Update(i.Name.Components, func(m map[chan<- *Data]pitEntry) map[chan<- *Data]pitEntry {
		if m == nil {
			m = make(map[chan<- *Data]pitEntry)
		}
		for _, e := range m {
			if reflect.DeepEqual(e.Selectors, &i.Selectors) {
				goto PIT_DONE
			}
		}
		f.wm.Lock()
		i.WriteTo(f.Writer)
		f.wm.Unlock()
	PIT_DONE:
		m[ch] = pitEntry{
			Selectors: &i.Selectors,
			timer:     timer,
		}
		return m
	}, false)
	f.pitm.Unlock()

	return ch
}

func (f *face) recvData(d *Data) {
	f.pitm.Lock()
	f.UpdateAll(d.Name.Components, func(name []lpm.Component, m map[chan<- *Data]pitEntry) map[chan<- *Data]pitEntry {
		for ch, e := range m {
			if !e.Match(d, len(name)) {
				continue
			}
			ch <- d
			close(ch)
			e.timer.Stop()
			delete(m, ch)
		}
		if len(m) == 0 {
			return nil
		}
		return m
	}, true)
	f.pitm.Unlock()
}

func (f *face) recvInterest(i *Interest) {
	if f.recv != nil {
		f.recv <- i
	}
}
