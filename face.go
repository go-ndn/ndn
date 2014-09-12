package ndn

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/taylorchu/tlv"
	"net"
	"time"
)

type readFrom interface {
	readFrom(r tlv.PeekReader) (err error)
}

type writeTo interface {
	writeTo(w tlv.Writer) (err error)
}

type Face struct {
	id uint64
	r  tlv.PeekReader
	w  tlv.Writer
	c  net.Conn
}

// NewFace creates PIT-free face to avoid O(N) PIT lookup, but the face is not reusable
//
// Common local nfd address: "localhost:6363", "/var/run/nfd.sock"
//
// Known networks are "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only),
// "udp", "udp4" (IPv4-only), "udp6" (IPv6-only), "ip", "ip4"
// (IPv4-only), "ip6" (IPv6-only), "unix", "unixgram" and
// "unixpacket".
//
// For TCP and UDP networks, addresses have the form host:port.
// If host is a literal IPv6 address or host name, it must be enclosed
// in square brackets as in "[::1]:80", "[ipv6-host]:http" or
// "[ipv6-host%zone]:80".
// The functions JoinHostPort and SplitHostPort manipulate addresses
// in this form.
//
// Examples:
//	NewFace("tcp", "12.34.56.78:80")
//	NewFace("tcp", "google.com:http")
//	NewFace("tcp", "[2001:db8::1]:http")
//	NewFace("tcp", "[fe80::1%lo0]:80")
//
// For IP networks, the network must be "ip", "ip4" or "ip6" followed
// by a colon and a protocol number or name and the addr must be a
// literal IP address.
//
// Examples:
//	NewFace("ip4:1", "127.0.0.1")
//	NewFace("ip6:ospf", "::1")
//
// For Unix networks, the address must be a file system path.
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

type Handle struct {
	Interest chan *Interest
	Data     chan *Data
	Error    chan error
}

func (this *Face) verify(d *Data) (err error) {
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
	h, err := face.Dial(&Interest{
		Name: keyName,
	})
	if err != nil {
		return
	}
	select {
	case cd := <-h.Data:
		key := new(Key)
		err = key.DecodePublicKey(cd.Content)
		if err != nil {
			return
		}
		err = key.verify(digest, d.SignatureValue)
	case err = <-h.Error:
		return
	}
	return
}

// Dial expresses interest, and return a channel of segmented/sequenced data
func (this *Face) Dial(out writeTo) (h *Handle, err error) {
	err = out.writeTo(this.w)
	if err != nil {
		return
	}
	h = &Handle{
		Data:  make(chan *Data),
		Error: make(chan error, 1),
	}
	go func() {
		for {
			d := new(Data)
			switch i := out.(type) {
			case *Interest:
				this.c.SetDeadline(time.Now().Add(time.Duration(i.LifeTime) * time.Millisecond))
			case *ControlPacket:
				this.c.SetDeadline(time.Now().Add(time.Duration(i.LifeTime) * time.Millisecond))
			}
			err := d.readFrom(this.r)
			this.c.SetDeadline(time.Time{})
			if err != nil {
				h.Error <- err
				return
			}
			h.Data <- d
			name := d.Name
			last := name.Pop()
			if bytes.Equal(d.MetaInfo.FinalBlockId.Component, last) {
				return
			}
			m, err := last.Marker()
			if err != nil {
				return
			}
			n, err := last.Number()
			if err != nil {
				return
			}
			switch m {
			case Segment:
				fallthrough
			case Sequence:
				name.Push(m, n+1)
			case Offset:
				name.Push(m, n+uint64(len(d.Content)))
			default:
				return
			}
			err = (&Interest{Name: name}).writeTo(this.w)
			if err != nil {
				h.Error <- err
				return
			}
		}
	}()
	return
}

func (this *Face) create() (err error) {
	control := new(ControlPacket)
	control.Name.Module = "faces"
	control.Name.Command = "create"
	control.Name.Parameters.Parameters.Uri = this.c.LocalAddr().Network() + "://" + this.c.LocalAddr().String()
	h, err := this.Dial(control)
	if err != nil {
		return
	}
	select {
	case d := <-h.Data:
		var resp ControlResponse
		err = Unmarshal(d.Content, &resp, 101)
		if err != nil {
			return
		}
		if resp.StatusCode != 200 {
			err = fmt.Errorf("(%d) %s", resp.StatusCode, resp.StatusText)
			return
		}
		this.id = resp.Parameters.FaceId
	case err = <-h.Error:
		return
	}
	return
}

func (this *Face) announce(prefix string) (err error) {
	control := new(ControlPacket)
	control.Name.Module = "fib"
	control.Name.Command = "add-nexthop"
	control.Name.Parameters.Parameters.Name = NewName(prefix)
	control.Name.Parameters.Parameters.FaceId = this.id

	h, err := this.Dial(control)
	if err != nil {
		return
	}
	select {
	case d := <-h.Data:
		var resp ControlResponse
		err = Unmarshal(d.Content, &resp, 101)
		if err != nil {
			return
		}
		if resp.StatusCode != 200 {
			err = fmt.Errorf("(%d) %s", resp.StatusCode, resp.StatusText)
			return
		}
	case err = <-h.Error:
		return
	}
	return
}

// Listen registers prefix to nfd, and listens to incoming interests
//
// A server should read from interest channel and write to data channel.
// Data channel must be closed.
func (this *Face) Listen(prefix string) (h *Handle, err error) {
	err = this.create()
	if err != nil {
		return
	}
	err = this.announce(prefix)
	if err != nil {
		return
	}
	fmt.Printf("Listen(%d) %s %s://%s\n", this.id, prefix, this.c.LocalAddr().Network(), this.c.LocalAddr().String())
	h = &Handle{
		Interest: make(chan *Interest),
		Data:     make(chan *Data),
		Error:    make(chan error, 1),
	}
	go func() {
		for d := range h.Data {
			err := d.writeTo(this.w)
			if err != nil {
				h.Error <- err
				break
			}
		}
	}()
	go func() {
		for {
			i := new(Interest)
			err := i.readFrom(this.r)
			if err != nil {
				h.Error <- err
				break
			}
			h.Interest <- i
		}
	}()
	return
}
