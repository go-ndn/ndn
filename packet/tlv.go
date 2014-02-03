package packet

import (
	"bytes"
	"encoding/binary"
	//"log"
	"errors"
	"math"
)

type TLV struct {
	Type     uint64
	Length   uint64
	Value    []byte
	Children []*TLV
}

func ReadByte(buf *bytes.Reader) (result uint64, offset uint64, err error) {
	b, err := buf.ReadByte()
	if err != nil {
		return
	}
	switch b {
	case 0xFD:
		var v16 uint16
		err = binary.Read(buf, binary.BigEndian, &v16)
		if err != nil {
			return
		}
		result = uint64(v16)
		offset += 2
	case 0xFE:
		var v32 uint32
		err = binary.Read(buf, binary.BigEndian, &v32)
		if err != nil {
			return
		}
		result = uint64(v32)
		offset += 4
	case 0xFF:
		var v64 uint64
		err = binary.Read(buf, binary.BigEndian, &v64)
		if err != nil {
			return
		}
		result = v64
		offset += 8
	default:
		result = uint64(b)
		offset++
	}
	return
}

func WriteByte(buf *bytes.Buffer, v uint64) (err error) {
	switch {
	case v > math.MaxUint32:
		buf.WriteByte(0xFF)
		err = binary.Write(buf, binary.BigEndian, uint64(v))
	case v > math.MaxUint16:
		buf.WriteByte(0xFE)
		err = binary.Write(buf, binary.BigEndian, uint32(v))
	case v > math.MaxUint8:
		buf.WriteByte(0xFD)
		err = binary.Write(buf, binary.BigEndian, uint16(v))
	default:
		err = binary.Write(buf, binary.BigEndian, uint8(v))
	}
	return
}

func (this *TLV) Parse(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New(EMPTY_PARSE_BUFFER)
	}
	buf := bytes.NewReader(raw)
	t, tl, err := ReadByte(buf)
	if err != nil {
		return nil, err
	}
	this.Type = t
	l, ll, err := ReadByte(buf)
	if err != nil {
		return nil, err
	}
	this.Length = l
	if err != nil {
		return nil, err
	}
	if tl+ll < l && uint64(len(raw)) >= l {
		this.Value = raw[tl+ll : l]
	}
	return raw[l:], nil
}

func (this *TLV) Dump() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := WriteByte(buf, this.Type)
	if err != nil {
		return nil, err
	}
	err = WriteByte(buf, this.Length)
	if err != nil {
		return nil, err
	}
	if len(this.Value) != 0 && len(this.Children) != 0 {
		return nil, errors.New(VALUE_CHILDREN_COEXIST)
	}
	if len(this.Value) == 0 {
		for _, c := range this.Children {
			b, err := c.Dump()
			if err != nil {
				return nil, err
			}
			buf.Write(b)
		}
	} else {
		buf.Write(this.Value)
	}
	return buf.Bytes(), nil
}
