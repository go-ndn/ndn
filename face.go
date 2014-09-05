package ndn

import (
	"bufio"
	"fmt"
	"github.com/taylorchu/tlv"
	"io"
	"net"
	"net/url"
)

type ReadFrom interface {
	ReadFrom(r tlv.PeekReader) (err error)
}

type WriteTo interface {
	WriteTo(w tlv.Writer) (err error)
}

type Face struct {
	id     uint64
	addr   string // local address
	r      tlv.PeekReader
	w      tlv.Writer
	closer io.Closer
}

func NewFace(addr string) (f *Face, err error) {
	u, err := url.Parse(addr)
	if err != nil {
		return
	}
	conn, err := net.Dial(u.Scheme, u.Host)
	if err != nil {
		return
	}
	f = &Face{
		r:      bufio.NewReader(conn),
		w:      conn,
		closer: conn,
		addr:   u.Scheme + "://" + conn.LocalAddr().String(),
	}
	// nfd create face
	err = f.create()
	if err != nil {
		return
	}
	fmt.Printf("Create(%d) %s\n", f.id, f.addr)
	return
}

func (this *Face) Close() error {
	return this.closer.Close()
}

func (this *Face) Dial(i *Interest) (d *Data, err error) {
	d = new(Data)
	err = this.dial(i, d)
	return
}

func (this *Face) dial(out WriteTo, in ReadFrom) (err error) {
	err = out.WriteTo(this.w)
	if err != nil {
		return
	}
	err = in.ReadFrom(this.r)
	return
}

func (this *Face) create() (err error) {
	control := new(ControlPacket)
	control.Name.Module = "faces"
	control.Name.Command = "create"
	control.Name.Parameters.Parameters.Uri = this.addr
	controlResponse := new(ControlResponsePacket)
	err = this.dial(control, controlResponse)
	if err != nil {
		return
	}
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
		control.Name.Parameters.Parameters.Name.Set(prefix)
		control.Name.Parameters.Parameters.FaceId = this.id

		controlResponse := new(ControlResponsePacket)
		err := this.dial(control, controlResponse)
		if err != nil {
			return err
		}
		if controlResponse.Content.Response.StatusCode != 200 {
			return fmt.Errorf("(%d) %s", controlResponse.Content.Response.StatusCode, controlResponse.Content.Response.StatusText)
		}
	}
	return nil
}

func (this *Face) Listen(handler func(*Interest) (*Data, error)) (err error) {
	for {
		packet := new(Interest)
		err = packet.ReadFrom(this.r)
		if err != nil {
			fmt.Println(err)
			continue
		}
		go func(in *Interest) {
			out, err := handler(in)
			if err != nil {
				fmt.Println(err)
				return
			}
			err = out.WriteTo(this.w)
			if err != nil {
				fmt.Println(err)
				return
			}
		}(packet)
	}
}
