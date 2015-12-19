package ndn

import (
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/go-ndn/lpm"
	"github.com/go-ndn/tlv"
)

type Sender interface {
	SendInterest(*Interest) <-chan *Data
	SendData(*Data)
}

type Face interface {
	Sender
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}

type face struct {
	net.Conn
	tlv.Reader  // read
	tlv.Writer  // write
	sync.Mutex  // write mutex
	lpm.Matcher // pit
	recv        chan<- *Interest
}

type pitEntry struct {
	*Selectors
	timer *time.Timer
}

func NewFace(transport net.Conn, ch chan<- *Interest) Face {
	f := &face{
		Conn:    transport,
		Reader:  tlv.NewReader(transport),
		Writer:  tlv.NewWriter(transport),
		Matcher: lpm.NewThreadSafe(),
		recv:    ch,
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
	f.Lock()
	d.WriteTo(f.Writer)
	f.Unlock()
}

func (f *face) SendInterest(i *Interest) <-chan *Data {
	ch := make(chan *Data, 1)
	name := i.Name.String()

	lifeTime := 4 * time.Second
	if i.LifeTime != 0 {
		lifeTime = time.Duration(i.LifeTime) * time.Millisecond
	}
	timer := time.AfterFunc(lifeTime, func() {
		f.Update(name, func(v interface{}) interface{} {
			if v == nil {
				return nil
			}
			m := v.(map[chan<- *Data]pitEntry)
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
	})

	f.Update(name, func(v interface{}) interface{} {
		var m map[chan<- *Data]pitEntry
		if v == nil {
			m = make(map[chan<- *Data]pitEntry)
		} else {
			m = v.(map[chan<- *Data]pitEntry)
		}
		for _, e := range m {
			if reflect.DeepEqual(e.Selectors, &i.Selectors) {
				goto PIT_DONE
			}
		}
		f.Lock()
		i.WriteTo(f.Writer)
		f.Unlock()
	PIT_DONE:
		m[ch] = pitEntry{
			Selectors: &i.Selectors,
			timer:     timer,
		}
		return m
	}, false)

	return ch
}

func (f *face) recvData(d *Data) {
	f.UpdateAll(d.Name.String(), func(name string, v interface{}) interface{} {
		m := v.(map[chan<- *Data]pitEntry)
		for ch, e := range m {
			if !e.Match(name, d) {
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
}

func (f *face) recvInterest(i *Interest) {
	if f.recv != nil {
		f.recv <- i
	}
}
