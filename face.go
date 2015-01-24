package ndn

import (
	"bufio"
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/go-ndn/exact"
	"github.com/go-ndn/lpm"
	"github.com/go-ndn/tlv"
)

type Face struct {
	w            net.Conn
	r            tlv.PeekReader
	pit          *lpm.Matcher
	interestRecv chan<- *Interest
}

var (
	ContentStore = exact.New()
)

// NewFace create a face with transport and interest buffer
//
// The interest buffer will be closed.
// All incoming interests will be ignored if nil interest channel is passed in.
func NewFace(transport net.Conn, ch chan<- *Interest) (f *Face) {
	f = &Face{
		w:            transport,
		r:            bufio.NewReader(transport),
		pit:          lpm.New(),
		interestRecv: ch,
	}
	go func() {
		for {
			d := new(Data)
			err := d.ReadFrom(f.r)
			if err == nil {
				f.recvData(d)
				continue
			}

			i := new(Interest)
			err = i.ReadFrom(f.r)
			if err == nil {
				f.recvInterest(i)
				continue
			}
			break
		}
		if f.interestRecv != nil {
			close(f.interestRecv)
		}
	}()
	return
}

func (this *Face) LocalAddr() net.Addr {
	return this.w.LocalAddr()
}

func (this *Face) RemoteAddr() net.Addr {
	return this.w.RemoteAddr()
}

func (this *Face) Close() error {
	return this.w.Close()
}

func (this *Face) SendData(d *Data) error {
	return d.WriteTo(this.w)
}

func (this *Face) SendInterest(i *Interest) (<-chan *Data, error) {
	ch := make(chan *Data, 1)
	var inCache bool
	ContentStore.Update(i.Name, func(v interface{}) interface{} {
		if v == nil {
			return nil
		}
		name := i.Name.String()
		for d, t := range v.(map[*Data]time.Time) {
			if i.Selectors.Match(name, d, t) {
				ch <- d
				close(ch)
				inCache = true
				break
			}
		}
		return v
	})
	if inCache {
		// found in cache
		return ch, nil
	}
	var err error
	this.pit.Update(i.Name, func(chs interface{}) interface{} {
		var m map[chan<- *Data]*Selectors
		if chs == nil {
			m = make(map[chan<- *Data]*Selectors)
		} else {
			m = chs.(map[chan<- *Data]*Selectors)
		}
		var inPit bool
		for _, sel := range m {
			if reflect.DeepEqual(sel, &i.Selectors) {
				inPit = true
				break
			}
		}
		if !inPit {
			err = i.WriteTo(this.w)
			if err != nil {
				return m
			}
		}
		m[ch] = &i.Selectors
		return m
	}, false)

	if err != nil {
		return nil, err
	}

	go func() {
		lifeTime := 4 * time.Second
		if i.LifeTime != 0 {
			lifeTime = time.Duration(i.LifeTime) * time.Millisecond
		}
		time.Sleep(lifeTime)

		this.pit.Update(i.Name, func(chs interface{}) interface{} {
			if chs == nil {
				return nil
			}
			m := chs.(map[chan<- *Data]*Selectors)
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

	return ch, nil
}

func (this *Face) recvData(d *Data) (err error) {
	ContentStore.Update(d.Name, func(v interface{}) interface{} {
		var m map[*Data]time.Time
		if v == nil {
			m = make(map[*Data]time.Time)
		} else {
			m = v.(map[*Data]time.Time)
		}
		m[d] = time.Now()
		return m
	})
	this.pit.UpdateAll(d.Name, func(name string, chs interface{}) interface{} {
		m := chs.(map[chan<- *Data]*Selectors)
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
	return
}

func (this *Face) recvInterest(i *Interest) (err error) {
	if this.interestRecv != nil {
		this.interestRecv <- i
	}
	return
}

func (this *Face) Register(prefix string) error {
	return this.SendControl("rib", "register", &Parameters{Name: NewName(prefix)})
}

func (this *Face) Unregister(prefix string) error {
	return this.SendControl("rib", "unregister", &Parameters{Name: NewName(prefix)})
}

func (this *Face) SendControl(module, command string, params *Parameters) (err error) {
	c := new(Command)
	c.Module = module
	c.Command = command
	c.Parameters.Parameters = *params
	i := new(Interest)
	err = Copy(c, &i.Name)
	if err != nil {
		return
	}
	ch, err := this.SendInterest(i)
	if err != nil {
		return
	}
	d, ok := <-ch
	if !ok {
		err = fmt.Errorf("control response timeout")
		return
	}
	resp := new(ControlResponse)
	err = Unmarshal(d.Content, resp, 101)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("(%d) %s", resp.StatusCode, resp.StatusText)
		return
	}
	return
}
