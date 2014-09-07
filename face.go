package ndn

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/taylorchu/tlv"
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
	id uint64
	r  tlv.PeekReader
	w  tlv.Writer
	c  net.Conn
}

func NewFace(network, address string) (f *Face, err error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return
	}
	f = &Face{
		r: bufio.NewReader(conn),
		w: conn,
		c: conn,
	}
	return
}

func (this *Face) Close() error {
	return this.c.Close()
}

func (this *Face) Dial(i *Interest) (dc chan *Data) {
	c := this.dial(i, func() ReadFrom { return new(Data) })
	dc = make(chan *Data)
	go func() {
		for p := range c {
			dc <- p.(*Data)
		}
		close(dc)
	}()
	return
}

func (this *Face) Verify(d *Data) (err error) {
	// digest
	digest, err := newSha256(d)
	if err != nil {
		return
	}
	keyName := d.SignatureInfo.KeyLocator.Name
	var face *Face
	face, err = NewFace(this.c.RemoteAddr().Network(), this.c.RemoteAddr().String())
	if err != nil {
		return
	}
	defer face.Close()
	c := face.Dial(&Interest{
		Name: keyName,
	})
	cd, ok := <-c
	if !ok {
		err = fmt.Errorf("verify: %v cannot fetch %v", d.Name, keyName)
		return
	}
	key := new(Key)
	err = key.DecodeCertificate(cd.Content)
	if err != nil {
		return
	}
	err = key.Verify(digest, d.SignatureValue)
	return
}

func (this *Face) dial(out WriteTo, in func() ReadFrom) (c chan ReadFrom) {
	c = make(chan ReadFrom)
	go func() {
		out.WriteTo(this.w)
		for {
			p := in()
			this.c.SetDeadline(time.Now().Add(4 * time.Second))
			err := p.ReadFrom(this.r)
			this.c.SetDeadline(time.Time{})
			if err != nil {
				goto EXIT
			}
			// switch d := p.(type) {
			// case *Data:
			// 	err := this.Verify(d)
			// 	if err != nil {
			// 		fmt.Println(err)
			// 		goto EXIT
			// 	}
			// }
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
				(&Interest{
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

func (this *Face) create() (err error) {
	control := new(ControlPacket)
	control.Name.Module = "faces"
	control.Name.Command = "create"
	control.Name.Parameters.Parameters.Uri = this.c.LocalAddr().Network() + "://" + this.c.LocalAddr().String()
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

func (this *Face) announce(prefixList ...string) error {
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

func (this *Face) Listen(prefixList ...string) (ic chan *Interest, dc chan *Data) {
	ic = make(chan *Interest)
	dc = make(chan *Data)
	// nfd create face
	err := this.create()
	if err != nil {
		close(ic)
		fmt.Println(err)
		return
	}
	fmt.Printf("Create(%d) %s://%s\n", this.id, this.c.LocalAddr().Network(), this.c.LocalAddr().String())
	err = this.announce(prefixList...)
	if err != nil {
		close(ic)
		fmt.Println(err)
		return
	}

	go func() {
		for d := range dc {
			d.WriteTo(this.w)
		}
	}()
	go func() {
		for {
			i := new(Interest)
			err := i.ReadFrom(this.r)
			if err != nil {
				fmt.Println(err)
				break
			}
			ic <- i
		}
		close(ic)
	}()
	return
}
