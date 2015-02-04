package ndn

import (
	"errors"
	"net"
	"reflect"
	"time"

	"github.com/go-ndn/exact"
	"github.com/go-ndn/lpm"
	"github.com/go-ndn/tlv"
)

var (
	ErrTimeout        = errors.New("timeout")
	ErrResponseStatus = errors.New("bad command response status")
)

type Face struct {
	w            net.Conn
	r            tlv.Reader
	pit          lpm.Matcher
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
		r:            tlv.NewReader(transport),
		pit:          lpm.NewThreadSafe(),
		interestRecv: ch,
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

func (this *Face) recvData(d *Data) {
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
}

func (this *Face) recvInterest(i *Interest) {
	if this.interestRecv != nil {
		this.interestRecv <- i
	}
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
		err = ErrTimeout
		return
	}
	resp := new(ControlResponse)
	err = Unmarshal(d.Content, resp, 101)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = ErrResponseStatus
		return
	}
	return
}
