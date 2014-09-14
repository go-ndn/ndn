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

func (this *Face) newConn() (nc *conn, err error) {
	c, err := net.Dial(this.Network, this.Address)
	if err != nil {
		return
	}
	nc = &conn{
		c: c,
		r: bufio.NewReader(c),
	}
	return
}

func (this *Face) verify(d *Data) (err error) {
	digest, err := newSha256(d)
	if err != nil {
		return
	}
	dl, err := this.Dial(&Interest{
		Name: d.SignatureInfo.KeyLocator.Name,
	})
	if err != nil {
		return
	}
	cd, err := dl.Receive()
	if err != nil {
		return
	}
	var key Key
	err = key.DecodePublicKey(cd.Content)
	if err != nil {
		return
	}
	err = key.verify(digest, d.SignatureValue)
	return
}

// Dial expresses interest, and waits for segmented/sequenced data
func (this *Face) Dial(out writeTo) (dl Dialer, err error) {
	conn, err := this.newConn()
	if err != nil {
		return
	}
	err = out.writeTo(conn.c)
	if err != nil {
		return
	}
	switch i := out.(type) {
	case *Interest:
		conn.timeout = time.Duration(i.LifeTime)
	case *ControlPacket:
		conn.timeout = time.Duration(i.LifeTime)
	}
	dl = conn
	return
}

// Listen registers prefix to nfd, and listens to incoming interests
func (this *Face) Listen(prefix string) (ln Listener, err error) {
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
	ln = conn
	return
}

type Dialer interface {
	Receive() (*Data, error)
	Close() error
}

type Listener interface {
	Accept() (*Interest, error)
	Send(*Data) error
	Close() error
}

type conn struct {
	c       net.Conn
	r       tlv.PeekReader
	timeout time.Duration
}

func (this *conn) Close() error {
	return this.c.Close()
}

func (this *conn) Accept() (i *Interest, err error) {
	i = new(Interest)
	err = i.readFrom(this.r)
	return
}

func (this *conn) Send(d *Data) error {
	return d.writeTo(this.c)
}

func (this *conn) Receive() (d *Data, err error) {
	// assume non-segment
	timeout := this.timeout
	this.timeout = 0

	d = new(Data)
	this.c.SetDeadline(time.Now().Add(timeout * time.Millisecond))
	err = d.readFrom(this.r)
	this.c.SetDeadline(time.Time{})
	if err != nil {
		return
	}
	name := d.Name
	last := name.Pop()
	if bytes.Equal(d.MetaInfo.FinalBlockId.Component, last) {
		return
	}
	m, err := last.Marker()
	if err != nil {
		err = nil
		return
	}
	n, err := last.Number()
	if err != nil {
		err = nil
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
	err = (&Interest{Name: name}).writeTo(this.c)
	if err != nil {
		return
	}
	this.timeout = timeout
	return
}

func (this *conn) getResponse(control *ControlPacket) (resp *ControlResponse, err error) {
	err = control.writeTo(this.c)
	if err != nil {
		return
	}
	var d Data
	err = d.readFrom(this.r)
	if err != nil {
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

func (this *conn) createFace() (id uint64, err error) {
	control := new(ControlPacket)
	control.Name.Module = "faces"
	control.Name.Command = "create"
	control.Name.Parameters.Parameters.Uri = this.c.LocalAddr().Network() + "://" + this.c.LocalAddr().String()
	resp, err := this.getResponse(control)
	if err != nil {
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
	_, err = this.getResponse(control)
	return
}
