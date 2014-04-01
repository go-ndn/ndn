package ndn

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	//"github.com/davecgh/go-spew/spew"
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
func readChunk(rw *bufio.ReadWriter) (b []byte, err error) {
	// type and length are at most 1+8+1+8 bytes
	peek, _ := rw.Peek(18)
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
	_, err = rw.Read(b)
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
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	// write interest
	_, err = rw.Write(ib)
	if err != nil {
		return
	}
	err = rw.Flush()
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
	b, err := readChunk(rw)
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

func dialControl(rw *bufio.ReadWriter, c *Control) (cr *ControlResponse, err error) {
	i, err := c.Interest()
	if err != nil {
		return
	}
	b, err := i.Encode()
	if err != nil {
		return
	}
	_, err = rw.Write(b)
	if err != nil {
		return
	}
	err = rw.Flush()
	if err != nil {
		return
	}
	// get control response
	b, err = readChunk(rw)
	if err != nil {
		return
	}
	d := &Data{}
	err = d.Decode(b)
	if err != nil {
		// invalid data
		return
	}
	cr = &ControlResponse{}
	err = cr.Data(d)
	if err != nil {
		// invalid control response
		return
	}
	return
}

func (this *Face) Run() error {
	// dial
	conn, err := net.Dial(this.Scheme, this.Host)
	if err != nil {
		return err
	}
	defer conn.Close()
	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	// nfd create face
	addr := "tcp://" + conn.LocalAddr().String()
	cr, err := dialControl(rw, &Control{
		Module:  "faces",
		Command: "create",
		Parameters: Parameters{
			Uri: addr,
		},
	})
	if err != nil {
		return err
	}
	if cr.StatusCode != 200 {
		return errors.New(fmt.Sprintf("(%d) %s", cr.StatusCode, cr.StatusText))
	}
	//spew.Dump(cr)
	// find faceId
	found := false
	var faceId uint64
	if len(cr.Body) == 1 {
		for _, c := range cr.Body[0].Children {
			if c.Type == FACE_ID {
				faceId, err = decodeNonNeg(c.Value)
				if err != nil {
					return err
				}
				found = true
			}
		}
	}
	if !found {
		return errors.New(FACE_ID_NOT_FOUND)
	}
	// announce prefix
	for prefix := range this.Handlers {
		cr, err := dialControl(rw, &Control{
			Module:  "fib",
			Command: "add-nexthop",
			Parameters: Parameters{
				Name:   nameFromString(prefix),
				FaceId: faceId,
			},
		})
		if err != nil {
			return err
		}
		if cr.StatusCode != 200 {
			return errors.New(fmt.Sprintf("%s: (%d) %s", prefix, cr.StatusCode, cr.StatusText))
		}
	}
	fmt.Printf("Listen %s\n", addr)
	for {
		// keep reading chunks and decode as interest
		b, err := readChunk(rw)
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
			rw.Write(b)
			rw.Flush()
		}(h, i)
	}
}
