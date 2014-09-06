package ndn

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/taylorchu/tlv"
	"io"
	"net"
	"time"
)

type ReadFrom interface {
	ReadFrom(r tlv.PeekReader) (err error)
}

type WriteTo interface {
	WriteTo(w tlv.Writer) (err error)
}

type Face struct {
	id     uint64
	r      tlv.PeekReader
	w      tlv.Writer
	closer io.Closer
}

func NewFace(network, address string) (f *Face, err error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return
	}
	addr := network + "://" + conn.LocalAddr().String()
	f = &Face{
		r:      bufio.NewReader(conn),
		w:      conn,
		closer: conn,
	}
	// nfd create face
	err = f.create(addr)
	if err != nil {
		return
	}
	fmt.Printf("Create(%d) %s\n", f.id, addr)
	return
}

func (this *Face) Close() error {
	return this.closer.Close()
}

func (this *Face) Dial(i *Interest) (dc chan *Data) {
	c := this.dial(i, func() ReadFrom { return new(Data) })
	timeout := time.Duration(i.LifeTime) * time.Millisecond
	dc = make(chan *Data)
	go func() {
		this.closer.(net.Conn).SetDeadline(time.Now().Add(timeout))
		for p := range c {
			dc <- p.(*Data)
			this.closer.(net.Conn).SetDeadline(time.Now().Add(timeout))
		}
		this.closer.(net.Conn).SetDeadline(time.Time{})
		close(dc)
	}()
	return
}

func (this *Face) dial(out WriteTo, in func() ReadFrom) (c chan ReadFrom) {
	out.WriteTo(this.w)
	c = make(chan ReadFrom)
	go func() {
		for {
			p := in()
			err := p.ReadFrom(this.r)
			if err != nil {
				goto EXIT
			}
			c <- p

			switch d := p.(type) {
			case *Data:
				name := d.Name
				last := name.Pop()
				if bytes.Equal(d.MetaInfo.FinalBlockId.Component, last) {
					goto EXIT
				}
				segn, err := last.To(Segment)
				if err != nil {
					goto EXIT
				}
				name.Push(Segment, segn+1)
				(&Data{
					Name: name,
				}).WriteTo(this.w)
			default:
				goto EXIT
			}
		}
	EXIT:
		close(c)
	}()
	return
}

func (this *Face) create(addr string) (err error) {
	control := new(ControlPacket)
	control.Name.Module = "faces"
	control.Name.Command = "create"
	control.Name.Parameters.Parameters.Uri = addr
	c := this.dial(control, func() ReadFrom { return new(ControlResponsePacket) })
	p, ok := <-c
	if !ok {
		fmt.Errorf("faces/create no response")
		return
	}
	controlResponse := p.(*ControlResponsePacket)
	if controlResponse.Content.Response.StatusCode != 200 {
		err = fmt.Errorf("(%d) %s", controlResponse.Content.Response.StatusCode, controlResponse.Content.Response.StatusText)
		return
	}
	this.id = controlResponse.Content.Response.Parameters.FaceId
	return
}

func (this *Face) Announce(prefixList ...string) error {
	for _, prefix := range prefixList {
		control := new(ControlPacket)
		control.Name.Module = "fib"
		control.Name.Command = "add-nexthop"
		control.Name.Parameters.Parameters.Name = NewName(prefix)
		control.Name.Parameters.Parameters.FaceId = this.id

		c := this.dial(control, func() ReadFrom { return new(ControlResponsePacket) })
		p, ok := <-c
		if !ok {
			return fmt.Errorf("fib/add-nexthop no response")
		}
		controlResponse := p.(*ControlResponsePacket)
		if controlResponse.Content.Response.StatusCode != 200 {
			return fmt.Errorf("(%d) %s", controlResponse.Content.Response.StatusCode, controlResponse.Content.Response.StatusText)
		}
	}
	return nil
}

func (this *Face) Listen() (ic chan *Interest, dc chan *Data) {
	ic = make(chan *Interest)
	dc = make(chan *Data)
	go func() {
		for d := range dc {
			err := d.WriteTo(this.w)
			if err != nil {
				fmt.Println(err)
				return
			}
		}
	}()
	go func() {
		i := new(Interest)
		err := i.ReadFrom(this.r)
		if err != nil {
			fmt.Println(err)
			close(ic)
			return
		}
		ic <- i
	}()
	return
}
