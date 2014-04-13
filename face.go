package ndn

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

/*
   Define ndn face
*/

// when interest comes, the handler should use data param to respond
// when data comes, interest will be nil
// because every interest and data matters, any bad packet(error returned) will end connection (non-recoverable)
type handler func(*Interest, *Data) error

type Face struct {
	Scheme   string
	Host     string
	Id       uint64
	Handlers map[string]handler
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
		Scheme:   u.Scheme,
		Host:     u.Host,
		Handlers: make(map[string]handler),
	}
	return
}

func peekType(rw *bufio.ReadWriter) (t uint64, err error) {
	peek, _ := rw.Peek(9)
	t, err = readByte(bytes.NewBuffer(peek))
	return
}

// read precisely one tlv
func readChunk(rw *bufio.ReadWriter) (b []byte, err error) {
	// type and length are at most 1+8+1+8 bytes
	peek, _ := rw.Peek(18)
	buf := bytes.NewBuffer(peek)
	// type
	_, err = readByte(buf)
	if err != nil {
		return
	}
	// length
	l, err := readByte(buf)
	if err != nil {
		return
	}
	b = make([]byte, int(l)+len(peek)-buf.Len())
	_, err = rw.Read(b)
	return
}

func readInterest(rw *bufio.ReadWriter) (i *Interest, err error) {
	b, err := readChunk(rw)
	if err != nil {
		return
	}
	i = &Interest{}
	err = i.Decode(b)
	return
}

func writeInterest(rw *bufio.ReadWriter, i *Interest) (err error) {
	b, err := i.Encode()
	if err != nil {
		return
	}
	_, err = rw.Write(b)
	if err != nil {
		return err
	}
	err = rw.Flush()
	return
}

func readData(rw *bufio.ReadWriter) (d *Data, err error) {
	b, err := readChunk(rw)
	if err != nil {
		return
	}
	d = &Data{}
	err = d.Decode(b)
	return
}

func writeData(rw *bufio.ReadWriter, d *Data) (err error) {
	b, err := d.Encode()
	if err != nil {
		return
	}
	_, err = rw.Write(b)
	if err != nil {
		return err
	}
	err = rw.Flush()
	return
}

func (this *Face) Dial(i *Interest) (d *Data, err error) {
	conn, err := net.Dial(this.Scheme, this.Host)
	if err != nil {
		return
	}
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	err = writeInterest(rw, i)
	if err != nil {
		return
	}
	if i.InterestLifeTime == 0 {
		// default timeout 10s
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	} else {
		// use interestLifeTime
		conn.SetReadDeadline(time.Now().Add(time.Duration(i.InterestLifeTime) * time.Millisecond))
	}
	// read one chunk only
	d, err = readData(rw)
	return
}

func dialControl(rw *bufio.ReadWriter, c *Control) (cr *ControlResponse, err error) {
	i, err := c.Encode()
	if err != nil {
		return
	}
	err = writeInterest(rw, i)
	if err != nil {
		return
	}
	d, err := readData(rw)
	if err != nil {
		// invalid data
		return
	}
	cr = &ControlResponse{}
	err = cr.Decode(d)
	return
}

func (this *Face) create(rw *bufio.ReadWriter, addr string) (err error) {
	cr, err := dialControl(rw, &Control{
		Module:  "faces",
		Command: "create",
		Parameters: Parameters{
			Uri: addr,
		},
	})
	if err != nil {
		return
	}
	if cr.StatusCode != STATUS_CODE_OK {
		err = errors.New(fmt.Sprintf("(%d) %s", cr.StatusCode, cr.StatusText))
		return
	}
	this.Id = cr.Parameters.FaceId
	return
}

func (this *Face) announcePrefix(rw *bufio.ReadWriter) error {
	for prefix := range this.Handlers {
		cr, err := dialControl(rw, &Control{
			Module:  "fib",
			Command: "add-nexthop",
			Parameters: Parameters{
				Name:   nameFromString(prefix),
				FaceId: this.Id,
			},
		})
		if err != nil {
			return err
		}
		if cr.StatusCode != STATUS_CODE_OK {
			return errors.New(fmt.Sprintf("%s: (%d) %s", prefix, cr.StatusCode, cr.StatusText))
		}
	}
	return nil
}

func (this *Face) On(name string, h handler) {
	this.Handlers[name] = h
}

// for server
func (this *Face) Listen() (err error) {
	conn, err := net.Dial(this.Scheme, this.Host)
	if err != nil {
		return
	}
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	addr := this.Scheme + "://" + conn.LocalAddr().String()
	// nfd create face
	if this.Id == 0 {
		err = this.create(rw, addr)
		if err != nil {
			return
		}
	}
	// announce prefix
	err = this.announcePrefix(rw)
	if err != nil {
		return
	}
	fmt.Printf("Listen(%d) %s\n", this.Id, addr)
	for {
		// keep reading chunks and decode as interest
		i, err := readInterest(rw)
		if err != nil {
			continue
		}
		go func(i *Interest) {
			h, ok := this.Handlers[nameToString(i.Name)]
			if !ok {
				return
			}
			d := &Data{}
			err := h(i, d)
			if err != nil {
				return
			}
			writeData(rw, d)
		}(i)
	}
}

// for forwarder
func (this *Face) ListenAny(h handler) (err error) {
	ln, err := net.Listen(this.Scheme, this.Host)
	if err != nil {
		return
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
			continue
		}
		// accepting new connection
		go func(conn net.Conn) {
			defer conn.Close()
			fmt.Printf("Forward %s\n", this.Scheme+"://"+conn.RemoteAddr().String())
			rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
			for {
				t, err := peekType(rw)
				if err != nil {
					return
				}
				switch t {
				case INTEREST:
					i, err := readInterest(rw)
					if err != nil {
						return
					}
					d := &Data{}
					err = h(i, d)
					if err != nil {
						return
					}
					err = writeData(rw, d)
					if err != nil {
						return
					}
				case DATA:
					d, err := readData(rw)
					if err != nil {
						return
					}
					err = h(nil, d)
					if err != nil {
						return
					}
				default:
					return
				}
			}
		}(conn)
	}
}
