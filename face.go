package ndn

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/taylorchu/tlv"
	"net"
	"net/url"
	"strings"
	"time"
)

type Encoder interface {
	Encode() (raw []byte, err error)
}

type Decoder interface {
	Decode(raw []byte) error
}

type Face struct {
	Scheme string
	Host   string
	Id     uint64
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
		Scheme: u.Scheme,
		Host:   u.Host,
	}
	return
}

// read precisely one tlv
func readChunk(rw *bufio.ReadWriter) (b []byte, err error) {
	// type and length are at most 1+8+1+8 bytes
	peek, _ := rw.Peek(18)
	buf := bytes.NewBuffer(peek)
	// type
	_, err = tlv.ReadBytes(buf)
	if err != nil {
		return
	}
	// length
	l, err := tlv.ReadBytes(buf)
	if err != nil {
		return
	}
	b = make([]byte, int(l)+len(peek)-buf.Len())
	_, err = rw.Read(b)
	return
}

func (this *Face) Dial(e Encoder, d Decoder) (err error) {
	conn, err := net.Dial(this.Scheme, this.Host)
	if err != nil {
		return
	}
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	err = this.dial(rw, e, d)
	return
}

func (this *Face) dial(rw *bufio.ReadWriter, e Encoder, d Decoder) (err error) {
	b, err := e.Encode()
	if err != nil {
		return
	}
	rw.Write(b)
	rw.Flush()
	// read one chunk only
	b, err = readChunk(rw)
	if err != nil {
		return
	}
	err = d.Decode(b)
	return
}

func (this *Face) create(rw *bufio.ReadWriter, addr string) (err error) {
	control := new(ControlPacket)
	control.Name.Module = "faces"
	control.Name.Command = "create"
	control.Name.ParamComponent.Parameters.Uri = addr
	controlResponse := new(ControlResponsePacket)
	err = this.dial(rw, control, controlResponse)
	if err != nil {
		return
	}
	if controlResponse.Content.Response.StatusCode != 200 {
		err = errors.New(fmt.Sprintf("(%d) %s", controlResponse.Content.Response.StatusCode, controlResponse.Content.Response.StatusText))
		return
	}
	this.Id = controlResponse.Content.Response.Parameters.FaceId
	return
}

func (this *Face) announcePrefix(rw *bufio.ReadWriter, prefixList []string) error {
	for _, prefix := range prefixList {
		control := new(ControlPacket)
		control.Name.Module = "fib"
		control.Name.Command = "add-nexthop"
		control.Name.ParamComponent.Parameters.Name = nameFromString(prefix)
		control.Name.ParamComponent.Parameters.FaceId = this.Id

		controlResponse := new(ControlResponsePacket)
		err := this.dial(rw, control, controlResponse)
		if err != nil {
			return err
		}
		if controlResponse.Content.Response.StatusCode != 200 {
			return errors.New(fmt.Sprintf("(%d) %s", controlResponse.Content.Response.StatusCode, controlResponse.Content.Response.StatusText))
		}
	}
	return nil
}

func (this *Face) Listen(prefixList []string, h func(b []byte) ([]byte, error)) (err error) {
	conn, err := net.Dial(this.Scheme, this.Host)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	addr := this.Scheme + "://" + conn.LocalAddr().String()
	// nfd create face
	if this.Id == 0 {
		err = this.create(rw, addr)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	// announce prefix
	err = this.announcePrefix(rw, prefixList)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Listen(%d) %s\n", this.Id, addr)
	for {
		// read one chunk only
		b, err := readChunk(rw)
		if err != nil {
			fmt.Println(err)
			continue
		}
		go func(b []byte) {
			b, err := h(b)
			if err != nil {
				fmt.Println(err)
				return
			}
			rw.Write(b)
			rw.Flush()
		}(b)
	}
}
