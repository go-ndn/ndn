package ndn

import (
	"bytes"
	"encoding/binary"
	"math"
)

/*
	Base TLV encoding
*/

type TLV struct {
	Type     uint64
	Value    []byte
	Children []TLV
}

func readByte(buf *bytes.Buffer) (result uint64, err error) {
	b, err := buf.ReadByte()
	if err != nil {
		return
	}
	switch b {
	case 0xFF:
		var v64 uint64
		err = binary.Read(buf, binary.BigEndian, &v64)
		if err != nil {
			return
		}
		result = v64
	case 0xFE:
		var v32 uint32
		err = binary.Read(buf, binary.BigEndian, &v32)
		if err != nil {
			return
		}
		result = uint64(v32)
	case 0xFD:
		var v16 uint16
		err = binary.Read(buf, binary.BigEndian, &v16)
		if err != nil {
			return
		}
		result = uint64(v16)
	default:
		result = uint64(b)
	}
	return
}

func writeByte(buf *bytes.Buffer, v uint64) (err error) {
	switch {
	case v > math.MaxUint32:
		buf.WriteByte(0xFF)
		err = binary.Write(buf, binary.BigEndian, v)
	case v > math.MaxUint16:
		buf.WriteByte(0xFE)
		err = binary.Write(buf, binary.BigEndian, uint32(v))
	case v > math.MaxUint8-3:
		buf.WriteByte(0xFD)
		err = binary.Write(buf, binary.BigEndian, uint16(v))
	default:
		err = binary.Write(buf, binary.BigEndian, uint8(v))
	}
	return
}

func (this *TLV) Decode(raw []byte) (b []byte, err error) {
	buf := bytes.NewBuffer(raw)
	this.Type, err = readByte(buf)
	if err != nil {
		return
	}
	l, err := readByte(buf)
	if err != nil {
		return
	}
	this.Value = buf.Next(int(l))
	b = buf.Bytes()
	return
}

func (this *TLV) Len() (length uint64) {
	if len(this.Value) == 0 {
		for _, c := range this.Children {
			l := c.Len()
			length += countBytes(c.Type) + countBytes(l) + l
		}
	} else {
		length = uint64(len(this.Value))
	}
	return
}

func (this *TLV) Add(n TLV) {
	this.Children = append(this.Children, n)
}

func countBytes(v uint64) (c uint64) {
	c = 1
	switch {
	case v > math.MaxUint32:
		c += 8
	case v > math.MaxUint16:
		c += 4
	case v > math.MaxUint8-3:
		c += 2
	}
	return
}

func (this *TLV) Encode() (b []byte, err error) {
	buf := new(bytes.Buffer)
	err = writeByte(buf, this.Type)
	if err != nil {
		return
	}
	err = writeByte(buf, this.Len())
	if err != nil {
		return
	}
	if len(this.Value) == 0 {
		for _, c := range this.Children {
			var e []byte
			e, err = c.Encode()
			if err != nil {
				return
			}
			buf.Write(e)
		}
	} else {
		buf.Write(this.Value)
	}
	b = buf.Bytes()
	return
}
