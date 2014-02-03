package packet

import (
	"bytes"
	"encoding/binary"
	//"log"
	"errors"
)

type TLV struct {
	Type     interface{}
	Length   interface{}
	Value    []byte
	Children []*TLV
}

func (this *TLV) GetType() uint64 {
	ret, _ := ToInt(this.Type)
	return ret
}

func (this *TLV) GetLength() uint64 {
	ret, _ := ToInt(this.Length)
	return ret
}

func ToInt(v interface{}) (ret uint64, err error) {
	switch v.(type) {
	case uint8:
		ret = uint64(v.(uint8))
	case uint16:
		ret = uint64(v.(uint16))
	case uint32:
		ret = uint64(v.(uint32))
	case uint64:
		ret = v.(uint64)
	default:
		err = errors.New(UNKNOWN_NUM_TYPE)
	}
	return
}

func ReadByte(buf *bytes.Reader) (result interface{}, offset uint64, err error) {
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
		result = v16
		offset += 2
	case 0xFE:
		var v32 uint32
		err = binary.Read(buf, binary.BigEndian, &v32)
		if err != nil {
			return
		}
		result = v32
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
		result = uint8(b)
		offset++
	}
	return
}

func WriteByte(buf *bytes.Buffer, v interface{}) (err error) {
	switch v.(type) {
	case uint16:
		buf.WriteByte(0xFD)
	case uint32:
		buf.WriteByte(0xFE)
	case uint64:
		buf.WriteByte(0xFF)
	}
	err = binary.Write(buf, binary.BigEndian, v)
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
	length, err := ToInt(l)
	if err != nil {
		return nil, err
	}
	if tl+ll < length && uint64(len(raw)) >= length {
		this.Value = raw[tl+ll : length]
	}
	return raw[length:], nil
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
