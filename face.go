package ndn

import (
	//"fmt"
	"bufio"
	"bytes"
	"net"
	"net/url"
	"strings"
	"time"
)

/*
   Define ndn face
*/

type Face struct {
	*url.URL
	Id       uint64
	Handlers map[string]func(*Interest) *Data
}

func NewFace(raw string) *Face {
	u, _ := url.Parse(raw)
	if len(u.Host) == 0 && len(u.Path) != 0 {
		u.Host = u.Path
		u.Path = ""
	}
	// assume tcp
	if len(u.Scheme) == 0 {
		u.Scheme = "tcp"
	}
	// assume port 6363
	if !strings.Contains(u.Host, ":") && (u.Scheme == "tcp" || u.Scheme == "udp") {
		u.Host += ":6363"
	}
	return &Face{
		URL:      u,
		Handlers: make(map[string]func(*Interest) *Data),
	}
}

// read precisely one tlv
func readChunk(r *bufio.Reader) (b []byte, err error) {
	// type and length are at most 1+8+1+8 bytes
	peek, _ := r.Peek(18)
	buf := bytes.NewBuffer(peek)
	_, err = readByte(buf)
	if err != nil {
		return
	}
	l, err := readByte(buf)
	if err != nil {
		return
	}
	b = make([]byte, int(l)+len(peek)-buf.Len())
	_, err = r.Read(b)
	return
}

func (this *Face) Dial(i *Interest) (d *Data, err error) {
	// interest encode
	ib, err := i.Encode()
	if err != nil {
		return
	}

	// dial
	conn, err := net.Dial(this.Scheme, this.Host)
	if err != nil {
		return
	}
	defer conn.Close()
	// write interest
	conn.Write(ib)
	if i.InterestLifeTime == 0 {
		// default timeout 10s
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	} else {
		// use interestLifeTime
		conn.SetReadDeadline(time.Now().Add(time.Duration(i.InterestLifeTime) * time.Millisecond))
	}
	// read one chunk only
	b, err := readChunk(bufio.NewReader(conn))
	if err != nil {
		return
	}
	d = &Data{}
	err = d.Decode(b)
	return
}

func (this *Face) Listen(name string, h func(*Interest) *Data) {
	this.Handlers[name] = h
}

func (this *Face) Run() error {
	// dial
	conn, err := net.Dial(this.Scheme, this.Host)
	if err != nil {
		return err
	}
	defer conn.Close()

	// TODO: nfd prefix annoucement

	r := bufio.NewReader(conn)
	for {
		// keep reading chunks and decode as interest
		b, err := readChunk(r)
		if err != nil {
			continue
		}
		i := &Interest{}
		err = i.Decode(b)
		if err != nil {
			// invalid interest
			continue
		}
		h, ok := this.Handlers[nameToString(i.Name)]
		if !ok {
			// handler not found
			continue
		}
		go func(h func(*Interest) *Data, i *Interest) {
			d := h(i)
			if d == nil {
				// handler ignore interest
				return
			}
			b, err := d.Encode()
			if err != nil {
				return
			}
			conn.Write(b)
		}(h, i)
	}
}
