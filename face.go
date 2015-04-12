package ndn

import (
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/go-ndn/exact"
	"github.com/go-ndn/lpm"
	"github.com/go-ndn/tlv"
)

type Face struct {
	w    net.Conn
	r    tlv.Reader
	pit  lpm.Matcher
	recv chan<- *Interest
	mu   sync.Mutex
}

var (
	ContentStore = exact.New()
)

func NewFace(transport net.Conn, ch chan<- *Interest) (f *Face) {
	f = &Face{
		w:    transport,
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
	return
}

func (f *Face) LocalAddr() net.Addr {
	return f.w.LocalAddr()
}

func (f *Face) RemoteAddr() net.Addr {
	return f.w.RemoteAddr()
}

func (f *Face) Close() error {
	return f.w.Close()
}

func (f *Face) SendData(d *Data) {
	f.mu.Lock()
	d.WriteTo(f.w)
	f.mu.Unlock()
}

func (f *Face) SendInterest(i *Interest) <-chan *Data {
	ch := make(chan *Data, 1)
	f.pit.Update(i.Name.String(), func(v interface{}) interface{} {
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
		f.mu.Lock()
		i.WriteTo(f.w)
		f.mu.Unlock()
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

		f.pit.Update(i.Name.String(), func(v interface{}) interface{} {
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

func (f *Face) recvData(d *Data) {
	f.pit.UpdateAll(d.Name.String(), func(name string, v interface{}) interface{} {
		m := v.(map[chan<- *Data]*Selectors)
		for ch, sel := range m {
			if !sel.Match(name, d, time.Time{}) {
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
	})
}

func (f *Face) recvInterest(i *Interest) {
	if f.recv != nil {
		f.recv <- i
	}
}
