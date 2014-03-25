package ndn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
)

type TLV struct {
	Type     uint64
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

func (this *TLV) Decode(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New(EMPTY_BUFFER)
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
	if tl+ll < l && uint64(len(raw)) >= l {
		this.Write(raw[tl+ll : l])
	}
	return raw[l:], nil
}

func (this *TLV) Length() (length uint64) {
	length = CountBytes(this.Type)
	if len(this.Value) == 0 {
		for _, c := range this.Children {
			length += c.Length()
		}
	} else {
		length += uint64(len(this.Value))
	}
	return CountBytes(length+CountBytes(length)) + length
}

func (this *TLV) Add(n *TLV) {
	this.Children = append(this.Children, n)
}

func (this *TLV) Get(t uint64) *TLV {
	for _, c := range this.Children {
		if c.Type == t {
			return c
		}
	}
	return nil
}

func (this *TLV) Read(v interface{}) {
	switch v.(type) {
	case *string:
		*v.(*string) = string(this.Value)
	case *bool:
		*v.(*bool) = len(this.Value) == 1 && this.Value[0] == 0x01
	default:
		binary.Read(bytes.NewBuffer(this.Value), binary.BigEndian, v)
	}
}

func (this *TLV) Write(v interface{}) {
	switch v.(type) {
	case nil:
		this.Value = nil
	case string:
		this.Value = []byte(v.(string))
	case bool:
		this.Value = []byte{0x01}
	default:
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, v)
		this.Value = buf.Bytes()
	}
}

func (this *TLV) Remove(t uint64) {
	for i, c := range this.Children {
		if c.Type == t {
			this.Children = append(this.Children[:i], this.Children[i+1:]...)
			break
		}
	}
}

func CountBytes(v uint64) uint64 {
	switch {
	case v > math.MaxUint32:
		return 8
	case v > math.MaxUint16:
		return 4
	case v > math.MaxUint8:
		return 2
	default:
		return 1
	}
}

func (this *TLV) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := WriteByte(buf, this.Type)
	if err != nil {
		return nil, err
	}

	err = WriteByte(buf, this.Length())
	if err != nil {
		return nil, err
	}
	if len(this.Value) != 0 && len(this.Children) != 0 {
		return nil, errors.New(VALUE_CHILDREN_COEXIST)
	}
	if len(this.Value) == 0 {
		for _, c := range this.Children {
			b, err := c.Encode()
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
