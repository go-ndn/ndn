package ndn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/url"
	"strings"
)

type Component []byte

type Name struct {
	Components []Component `tlv:"8"`
}

func NewName(s string) (n Name) {
	s = strings.Trim(s, "/")
	if s == "" {
		return
	}
	for _, c := range strings.Split(s, "/") {
		uc, _ := url.QueryUnescape(c)
		n.Components = append(n.Components, []byte(uc))
	}
	return
}

func encodeUint64(buf io.Writer, v uint64) (err error) {
	switch {
	case v > math.MaxUint32:
		err = binary.Write(buf, binary.BigEndian, v)
	case v > math.MaxUint16:
		err = binary.Write(buf, binary.BigEndian, uint32(v))
	case v > math.MaxUint8:
		err = binary.Write(buf, binary.BigEndian, uint16(v))
	default:
		err = binary.Write(buf, binary.BigEndian, uint8(v))
	}
	return
}

func decodeUint64(buf *bytes.Buffer) (v uint64, err error) {
	switch buf.Len() {
	case 8:
		err = binary.Read(buf, binary.BigEndian, &v)
	case 4:
		var v32 uint32
		err = binary.Read(buf, binary.BigEndian, &v32)
		v = uint64(v32)
	case 2:
		var v16 uint16
		err = binary.Read(buf, binary.BigEndian, &v16)
		v = uint64(v16)
	case 1:
		var v8 uint8
		err = binary.Read(buf, binary.BigEndian, &v8)
		v = uint64(v8)
	}
	return
}

type Marker uint8

const (
	Segment    Marker = 0x00
	ByteOffset        = 0xFB
	Version           = 0xFD
	Timestamp         = 0xFC
	Sequence          = 0xFE
)

func (this *Name) Equal(n Name) bool {
	if len(this.Components) != len(n.Components) {
		return false
	}
	for i := range this.Components {
		if !bytes.Equal(this.Components[i], n.Components[i]) {
			return false
		}
	}
	return true
}

func (this *Name) CertName() (name Name) {
	name.Components = append(this.Components, []byte("KEY"), []byte("ID-CERT"))
	return
}

func (this *Name) Push(m Marker, v uint64) (err error) {
	buf := new(bytes.Buffer)
	buf.WriteByte(uint8(m))
	err = encodeUint64(buf, v)
	if err != nil {
		return
	}
	this.Components = append(this.Components, buf.Bytes())
	return
}

func (this *Name) Pop() (c Component) {
	if len(this.Components) > 0 {
		c = this.Components[len(this.Components)-1]
		this.Components = this.Components[:len(this.Components)-1]
	}
	return
}

func (this Component) To(m Marker) (v uint64, err error) {
	if len(this) == 0 || this[0] != uint8(m) {
		err = fmt.Errorf("marker not found: %v", m)
		return
	}
	return decodeUint64(bytes.NewBuffer(this[1:]))
}

func (this Name) String() (name string) {
	if len(this.Components) == 0 {
		return "/"
	}
	for _, c := range this.Components {
		name += "/" + url.QueryEscape(string(c))
	}
	return
}
