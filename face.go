package ndn

import (
	"bufio"
	"fmt"
	"github.com/taylorchu/lpm"
	"github.com/taylorchu/tlv"
	"net"
	"time"
)

type Face struct {
	w          net.Conn
	r          tlv.PeekReader
	pit        *lpm.Matcher
	interestIn chan<- *Interest
}

var (
	ContentStore = lpm.New()
)

// NewFace create a face with transport and interest buffer
//
// The interest buffer will be closed.
// All incoming interests will be ignored if nil interest channel is passed in.
func NewFace(transport net.Conn, ch chan<- *Interest) (f *Face) {
	f = &Face{
		w:          transport,
		r:          bufio.NewReader(transport),
		pit:        lpm.New(),
		interestIn: ch,
	}
	go func() {
		for {
			d := new(Data)
			err := d.ReadFrom(f.r)
			if err == nil {
				f.recvData(d)
				continue
			}
			if f.interestIn != nil {
				i := new(Interest)
				err = i.ReadFrom(f.r)
				if err == nil {
					f.recvInterest(i)
					continue
				}
			}
			break
		}
		if f.interestIn != nil {
			close(f.interestIn)
		}
	}()
	return
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
	e := ContentStore.RMatch(i.Name)
	if e != nil {
		ch <- e.(*Data)
		close(ch)
		// found in cache
		return ch, nil
	}
	var err error
	this.pit.Update(i.Name, func(chs interface{}) interface{} {
		if chs == nil {
			// send interest only if it is new
			err = i.WriteTo(this.w)
			if err != nil {
				return nil
			}
			return map[chan<- *Data]bool{ch: true}
		}
		chs.(map[chan<- *Data]bool)[ch] = true
		return chs
	}, false)

	if err != nil {
		return nil, err
	}

	go func() {
		time.Sleep(time.Duration(i.LifeTime) * time.Millisecond)
		this.pit.Update(i.Name, func(chs interface{}) interface{} {
			if chs == nil {
				return nil
			}
			m := chs.(map[chan<- *Data]bool)
			if _, ok := m[ch]; !ok {
				return chs
			}
			close(ch)
			delete(m, ch)
			if len(m) == 0 {
				return nil
			}
			return chs
		}, false)
	}()

	return ch, nil
}

func (this *Face) recvData(d *Data) (err error) {
	this.pit.Update(d.Name, func(chs interface{}) interface{} {
		if chs == nil {
			return nil
		}
		for ch := range chs.(map[chan<- *Data]bool) {
			ch <- d
			close(ch)
		}
		ContentStore.Add(d.Name, d)
		if d.MetaInfo.FreshnessPeriod > 0 {
			go func() {
				time.Sleep(time.Duration(d.MetaInfo.FreshnessPeriod) * time.Millisecond)
				ContentStore.Remove(d.Name)
			}()
		}
		return nil
	}, true)
	return
}

func (this *Face) recvInterest(i *Interest) (err error) {
	this.interestIn <- i
	return
}

func (this *Face) verify(d *Data) (err error) {
	ch, err := this.SendInterest(&Interest{
		Name: d.SignatureInfo.KeyLocator.Name,
	})
	if err != nil {
		return
	}
	cd, ok := <-ch
	if !ok {
		err = fmt.Errorf("verify timeout")
		return
	}
	var key Key
	err = key.DecodePublicKey(cd.Content)
	if err != nil {
		return
	}
	err = key.Verify(d, d.SignatureValue)
	return
}

func (this *Face) AddNextHop(prefix string, cost uint64) (err error) {
	control := new(ControlInterest)
	control.Name.Module = "fib"
	control.Name.Command = "add-nexthop"
	control.Name.Parameters.Parameters.Name = NewName(prefix)
	control.Name.Parameters.Parameters.Cost = cost
	_, err = this.SendControlInterest(control)
	return
}

func (this *Face) RemoveNextHop(prefix string) (err error) {
	control := new(ControlInterest)
	control.Name.Module = "fib"
	control.Name.Command = "remove-nexthop"
	control.Name.Parameters.Parameters.Name = NewName(prefix)
	_, err = this.SendControlInterest(control)
	return
}

func (this *Face) SendControlInterest(control *ControlInterest) (resp *ControlResponse, err error) {
	i := new(Interest)
	err = Copy(control, i)
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
	resp = new(ControlResponse)
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
