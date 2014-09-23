package ndn

import (
	"bufio"
	"fmt"
	"github.com/taylorchu/lpm"
	"github.com/taylorchu/tlv"
	"net"
)

type Face struct {
	w          net.Conn
	r          tlv.PeekReader
	Pit        *lpm.Matcher
	Fib        *lpm.Matcher
	InterestIn chan *Interest
}

var (
	ContentStore = lpm.New()
)

func NewFace(transport net.Conn) (f *Face) {
	f = &Face{
		w:          transport,
		r:          bufio.NewReader(transport),
		Pit:        lpm.New(),
		Fib:        lpm.New(),
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
	this.Pit.Update(key, func(chs interface{}) interface{} {
		if chs == nil {
			return []chan *Data{ch}
		}
		return append(chs.([]chan *Data), ch)
	}, false)
	err = i.WriteTo(this.w)
	return
}

func (this *Face) RecvData(d *Data) (err error) {
	key := newLPMKey(d.Name)
	e := this.Pit.Match(key)
	if e == nil {
		// not in pit
		err = fmt.Errorf("data dropped; not in pit %s", d.Name)
		return
	}
	this.Pit.Update(key, func(chs interface{}) interface{} {
		for _, ch := range chs.([]chan *Data) {
			ch <- d
		}
		return nil
	}, true)
	ContentStore.Add(key, d)
	return
}

func (this *Face) RecvInterest(i *Interest) (err error) {
	this.InterestIn <- i
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
	cd := <-ch
	var key Key
	err = key.DecodePublicKey(cd.Content)
	if err != nil {
		return
	}
	err = key.verify(digest, d.SignatureValue)
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
	d := <-ch
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
