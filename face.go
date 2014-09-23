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
	InterestIn chan *Interest
}

var (
	ContentStore = lpm.New()
)

func NewFace(transport net.Conn) (f *Face) {
	f = &Face{
		w:          transport,
		r:          bufio.NewReader(transport),
		pit:        lpm.New(),
		InterestIn: make(chan *Interest),
	}
	go func() {
		for {
			d := new(Data)
			err := d.ReadFrom(f.r)
			if err == nil {
				f.RecvData(d)
				continue
			}
			i := new(Interest)
			err = i.ReadFrom(f.r)
			if err == nil {
				f.RecvInterest(i)
				continue
			}
			break
		}
		close(f.InterestIn)
	}()
	return
}

func (this *Face) RemoteAddr() net.Addr {
	return this.w.RemoteAddr()
}

func (this *Face) Close() error {
	return this.w.Close()
}

func newLPMKey(n Name) (cs []lpm.Component) {
	for _, c := range n.Components {
		cs = append(cs, lpm.Component(c))
	}
	return
}

func (this *Face) SendData(d *Data) error {
	return d.WriteTo(this.w)
}

func (this *Face) SendInterest(i *Interest) (ch chan *Data, err error) {
	key := newLPMKey(i.Name)
	ch = make(chan *Data, 1)
	e := ContentStore.RMatch(key)
	if e != nil {
		ch <- e.(*Data)
		// found in cache
		return
	}
	err = i.WriteTo(this.w)
	if err != nil {
		return
	}
	this.pit.Update(key, func(chs interface{}) interface{} {
		if chs == nil {
			return map[chan *Data]bool{ch: true}
		}
		chs.(map[chan *Data]bool)[ch] = true
		return chs
	}, false)

	go func() {
		<-time.After(time.Duration(i.LifeTime) * time.Millisecond)
		close(ch)
		this.pit.Update(key, func(chs interface{}) interface{} {
			if chs == nil {
				return nil
			}
			m := chs.(map[chan *Data]bool)
			delete(m, ch)
			if len(m) == 0 {
				return nil
			}
			return chs
		}, false)
	}()

	return
}

func (this *Face) RecvData(d *Data) (err error) {
	key := newLPMKey(d.Name)
	this.pit.Update(key, func(chs interface{}) interface{} {
		if chs == nil {
			return nil
		}
		for ch := range chs.(map[chan *Data]bool) {
			ch <- d
		}
		ContentStore.Add(key, d)
		return nil
	}, true)
	return
}

func (this *Face) RecvInterest(i *Interest) (err error) {
	go func() {
		this.InterestIn <- i
	}()
	return
}

func (this *Face) verify(d *Data) (err error) {
	digest, err := newSha256(d)
	if err != nil {
		return
	}
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
	err = key.Verify(digest, d.SignatureValue)
	return
}

func (this *Face) AddNextHop(prefix string) (err error) {
	control := new(ControlInterest)
	control.Name.Module = "fib"
	control.Name.Command = "add-nexthop"
	control.Name.Parameters.Parameters.Name = NewName(prefix)
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
