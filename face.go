package ndn

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/taylorchu/tlv"
	"io"
	"net"
	"net/url"
	"strings"
)

type ReadFrom interface {
	ReadFrom(r tlv.PeekReader) (err error)
}

type WriteTo interface {
	WriteTo(w tlv.Writer) (err error)
}

type Face struct {
	scheme string
	host   string
	id     uint64
	addr   string // local address
	r      tlv.PeekReader
	w      io.WriteCloser // tlv.Writer
}

func NewFace(raw string) (f *Face, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	if len(u.Scheme) == 0 || len(u.Host) == 0 {
		err = errors.New("scheme and host should not be empty")
		return
	}
	if !strings.Contains(u.Host, ":") && (strings.HasPrefix(u.Scheme, "tcp") || strings.HasPrefix(u.Scheme, "udp")) {
		err = errors.New("tcp and udp should have port number")
		return
	}
	f = &Face{
		scheme: u.Scheme,
		host:   u.Host,
	}
	conn, err := net.Dial(f.scheme, f.host)
	if err != nil {
		return
	}
	f.r = bufio.NewReader(conn)
	f.w = conn
	f.addr = f.scheme + "://" + conn.LocalAddr().String()
	// nfd create face
	err = f.create()
	return
}

func (this *Face) Close() error {
	return this.w.Close()
}

func (this *Face) Dial(out WriteTo, in ReadFrom) (err error) {
	err = this.dial(out, in)
	return
}

func (this *Face) dial(out WriteTo, in ReadFrom) (err error) {
	err = out.WriteTo(this.w)
	if err != nil {
		return
	}
	err = in.ReadFrom(this.r)
	if err != nil {
		Print(in)
		return
	}
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
		err = errors.New(fmt.Sprintf("(%d) %s", controlResponse.Content.Response.StatusCode, controlResponse.Content.Response.StatusText))
		return
	}
	this.id = controlResponse.Content.Response.Parameters.FaceId
	return
}

func (this *Face) announcePrefix(prefixList []string) error {
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
			return errors.New(fmt.Sprintf("(%d) %s", controlResponse.Content.Response.StatusCode, controlResponse.Content.Response.StatusText))
		}
	}
	return nil
}

func (this *Face) Listen(prefixList []string, packet ReadFrom, handler func(ReadFrom) (WriteTo, error)) (err error) {
	// announce prefix
	err = this.announcePrefix(prefixList)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Listen(%d) %s\n", this.id, this.addr)
	for {
		// read one chunk only
		err = packet.ReadFrom(this.r)
		if err != nil {
			fmt.Println(err)
			continue
		}
		go func(in ReadFrom) {
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
