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

// NewFace create a face with transport and interest channel
//
// The interest channel will be closed.
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

func (f *Face) LocalAddr() net.Addr {
	return f.w.LocalAddr()
}

func (f *Face) RemoteAddr() net.Addr {
	return f.w.RemoteAddr()
}

func (f *Face) Close() error {
	return f.w.Close()
}

func (f *Face) SendData(d *Data) error {
	return d.WriteTo(f.w)
}

func (f *Face) SendInterest(i *Interest) (<-chan *Data, error) {
	ch := make(chan *Data, 1)
	ContentStore.Update(i.Name, func(v interface{}) interface{} {
		if v == nil {
			return nil
		}
		name := i.Name.String()
		for d, t := range v.(map[*Data]time.Time) {
			if i.Selectors.Match(name, d, t) {
				ch <- d
				close(ch)
				break
			}
		}
		return v
	})
	if len(ch) > 0 {
		// found in cache
		return ch, nil
	}
	var err error
	f.pit.Update(i.Name, func(v interface{}) interface{} {
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
		err = i.WriteTo(f.w)
		if err != nil {
			return v
		}
	PIT_DONE:
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

		f.pit.Update(i.Name, func(v interface{}) interface{} {
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

	return ch, nil
}

func (f *Face) recvData(d *Data) {
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
	f.pit.UpdateAll(d.Name, func(name string, v interface{}) interface{} {
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
	if f.interestRecv != nil {
		f.interestRecv <- i
	}
}

func (f *Face) Register(prefix string, key *Key) error {
	return f.SendControl("rib", "register", &Parameters{Name: NewName(prefix)}, key)
}

func (f *Face) Unregister(prefix string, key *Key) error {
	return f.SendControl("rib", "unregister", &Parameters{Name: NewName(prefix)}, key)
}

func (f *Face) SendControl(module, command string, params *Parameters, key *Key) (err error) {
	cmd := &Command{
		Localhost: "localhost",
		NFD:       "nfd",
		Module:    module,
		Command:   command,
		Timestamp: uint64(time.Now().UTC().UnixNano() / 1000000),
		Nonce:     newNonce(),
	}
	cmd.Parameters.Parameters = *params
	cmd.SignatureInfo.SignatureInfo.SignatureType = key.SignatureType()
	cmd.SignatureInfo.SignatureInfo.KeyLocator.Name = key.Name
	cmd.SignatureValue.SignatureValue, err = key.sign(cmd)
	if err != nil {
		return
	}

	i := new(Interest)
	err = tlv.Copy(cmd, &i.Name)
	if err != nil {
		return
	}
	ch, err := f.SendInterest(i)
	if err != nil {
		return
	}
	d, ok := <-ch
	if !ok {
		err = ErrTimeout
		return
	}
	resp := new(ControlResponse)
	err = tlv.UnmarshalByte(d.Content, resp, 101)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = ErrResponseStatus
		return
	}
	return
}
