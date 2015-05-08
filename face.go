package ndn

import (
	"net"
	"reflect"
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
	r    tlv.Reader
	pit  lpm.Matcher
	recv chan<- *Interest
}

func NewFace(transport net.Conn, ch chan<- *Interest) Face {
	f := &face{
		Conn: transport,
		r:    tlv.NewReader(transport),
		pit:  lpm.NewThreadSafe(),
		recv: ch,
	}
	go func() {
		for {
			switch f.r.Peek() {
			case 5:
				i := new(Interest)
				err := i.ReadFrom(f.r)
				if err != nil {
					goto IDLE
				}
				f.recvInterest(i)
			case 6:
				d := new(Data)
				err := d.ReadFrom(f.r)
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
	d.WriteTo(f.Conn)
}

func (f *face) SendInterest(i *Interest) <-chan *Data {
	ch := make(chan *Data, 1)
	name := i.Name.String()
	f.pit.Update(name, func(v interface{}) interface{} {
		var m map[chan<- *Data]*Selectors
		if v == nil {
			m = make(map[chan<- *Data]*Selectors)
		} else {
			m = v.(map[chan<- *Data]*Selectors)
		}
		for _, sel := range m {
			if reflect.DeepEqual(sel, &i.Selectors) {
				goto PIT_DONE
			}
		}
		i.WriteTo(f.Conn)
	PIT_DONE:
		m[ch] = &i.Selectors
		return m
	}, false)

	go func() {
		lifeTime := 4 * time.Second
		if i.LifeTime != 0 {
			lifeTime = time.Duration(i.LifeTime) * time.Millisecond
		}
		time.Sleep(lifeTime)

		f.pit.Update(name, func(v interface{}) interface{} {
			if v == nil {
				return nil
			}
			m := v.(map[chan<- *Data]*Selectors)
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
	}()

	return ch
}

func (f *face) recvData(d *Data) {
	f.pit.UpdateAll(d.Name.String(), func(name string, v interface{}) interface{} {
		t := time.Time{}
		m := v.(map[chan<- *Data]*Selectors)
		for ch, sel := range m {
			if !sel.Match(name, d, t) {
				continue
			}
			ch <- d
			close(ch)
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
