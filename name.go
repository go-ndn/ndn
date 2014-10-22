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

// NewName creates a name from string representation
func NewName(s string) (n Name) {
	s = strings.Trim(s, "/")
	if s == "" {
		return
	}
	for _, c := range strings.Split(s, "/") {
		uc, _ := url.QueryUnescape(c)
		n.Components = append(n.Components, Component(uc))
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

// see http://named-data.net/doc/tech-memos/naming-conventions.pdf
const (
	Segment   Marker = 0x00
	Offset           = 0xFB
	Version          = 0xFD
	Timestamp        = 0xFC
	Sequence         = 0xFE
)

// Compare compares two names according to http://named-data.net/doc/ndn-tlv/name.html#canonical-order
//
// -1 if a < b; 0 if a == b; 1 if a > b
func (this *Name) Compare(n Name) int {
	for i := 0; i < len(this.Components) && i < len(n.Components); i++ {
		cmp := bytes.Compare(this.Components[i], n.Components[i])
		if cmp != 0 {
			return cmp
		}
	}
	if len(this.Components) < len(n.Components) {
		return -1
	}
	if len(this.Components) > len(n.Components) {
		return 1
	}
	return 0
}

func (this *Name) CertificateName() (name Name) {
	name.Components = append(this.Components, Component("KEY"), Component("ID-CERT"))
	return
}

// Push appends a new markerWithNumber to the end of the name
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

// Pop removes the last component from the name, and returns it
func (this *Name) Pop() (c Component) {
	if len(this.Components) > 0 {
		c = this.Components[len(this.Components)-1]
		this.Components = this.Components[:len(this.Components)-1]
	}
	return
}

// Marker returns the marker from name component
func (this Component) Marker() (m Marker, err error) {
	if len(this) == 0 {
		err = fmt.Errorf("no marker")
		return
	}
	switch Marker(this[0]) {
	case Segment:
		m = Segment
	case Offset:
		m = Offset
	case Version:
		m = Version
	case Timestamp:
		m = Timestamp
	case Sequence:
		m = Sequence
	default:
		err = fmt.Errorf("unsupported marker")
	}
	return
}

// Marker returns the number from name component
func (this Component) Number() (v uint64, err error) {
	_, err = this.Marker()
	if err != nil {
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
