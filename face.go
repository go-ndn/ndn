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
type Face struct {
	Network, Address string
}

type Handle struct {
	Interest chan *Interest
	Data     chan *Data
	Error    chan error
}

type conn struct {
	c net.Conn
	r tlv.PeekReader
	w tlv.Writer
}

func (this *Face) newConn() (nc *conn, err error) {
	c, err := net.Dial(this.Network, this.Address)
	if err != nil {
		return
	}
	nc = &conn{
		c: c,
		r: bufio.NewReader(c),
		w: c,
	}
	return
}

func (this *Face) verify(d *Data) (err error) {
	digest, err := newSha256(d)
	if err != nil {
		return
	}
	h, err := this.Dial(&Interest{
		Name: d.SignatureInfo.KeyLocator.Name,
	})
	if err != nil {
		return
	}
	select {
	case cd := <-h.Data:
		var key Key
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
	conn, err := this.newConn()
	if err != nil {
		return
	}
	err = out.writeTo(conn.w)
	if err != nil {
		return
	}
	h = &Handle{
		Data:  make(chan *Data),
		Error: make(chan error, 1),
	}
	go func() {
		defer conn.c.Close()
		for {
			d := new(Data)
			switch i := out.(type) {
			case *Interest:
				conn.c.SetDeadline(time.Now().Add(time.Duration(i.LifeTime) * time.Millisecond))
			case *ControlPacket:
				conn.c.SetDeadline(time.Now().Add(time.Duration(i.LifeTime) * time.Millisecond))
			}
			err := d.readFrom(conn.r)
			conn.c.SetDeadline(time.Time{})
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
			err = (&Interest{Name: name}).writeTo(conn.w)
			if err != nil {
				h.Error <- err
				return
			}
		}
	}()
	return
}

func (this *conn) createFace() (id uint64, err error) {
	control := new(ControlPacket)
	control.Name.Module = "faces"
	control.Name.Command = "create"
	control.Name.Parameters.Parameters.Uri = this.c.LocalAddr().Network() + "://" + this.c.LocalAddr().String()
	err = control.writeTo(this.w)
	if err != nil {
		return
	}
	var d Data
	err = d.readFrom(this.r)
	if err != nil {
		return
	}
	var resp ControlResponse
	err = Unmarshal(d.Content, &resp, 101)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("(%d) %s", resp.StatusCode, resp.StatusText)
		return
	}
	id = resp.Parameters.FaceId
	return
}

func (this *conn) announce(id uint64, prefix string) (err error) {
	control := new(ControlPacket)
	control.Name.Module = "fib"
	control.Name.Command = "add-nexthop"
	control.Name.Parameters.Parameters.Name = NewName(prefix)
	control.Name.Parameters.Parameters.FaceId = id
	err = control.writeTo(this.w)
	if err != nil {
		return
	}
	var d Data
	err = d.readFrom(this.r)
	if err != nil {
		return
	}
	var resp ControlResponse
	err = Unmarshal(d.Content, &resp, 101)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("(%d) %s", resp.StatusCode, resp.StatusText)
		return
	}
	return
}

// Listen registers prefix to nfd, and listens to incoming interests
//
// A server should read from interest channel and write to data channel.
// Data channel must be closed.
func (this *Face) Listen(prefix string) (h *Handle, err error) {
	conn, err := this.newConn()
	if err != nil {
		return
	}
	id, err := conn.createFace()
	if err != nil {
		return
	}
	err = conn.announce(id, prefix)
	if err != nil {
		return
	}
	fmt.Printf("Listen(%d) %s %s://%s\n", id, prefix, conn.c.LocalAddr().Network(), conn.c.LocalAddr().String())
	h = &Handle{
		Interest: make(chan *Interest),
		Data:     make(chan *Data),
		Error:    make(chan error, 1),
	}
	go func() {
		defer conn.c.Close()
		for d := range h.Data {
			err := d.writeTo(conn.w)
			if err != nil {
				h.Error <- err
				break
			}
		}
	}()
	go func() {
		for {
			i := new(Interest)
			err := i.readFrom(conn.r)
			if err != nil {
				h.Error <- err
				break
			}
			h.Interest <- i
		}
	}()
	return
}
