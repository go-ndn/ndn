package packet

import (
	"bytes"
	"encoding/binary"
	//"log"
	"errors"
)

type tlv struct {
	Type     interface{}
	Length   interface{}
	Value    []byte
	Children []*tlv
}

func ToInt(v interface{}) (uint64, error) {
	switch v.(type) {
	case uint8:
		return uint64(v.(uint8)), nil
	case uint16:
		return uint64(v.(uint16)), nil
	case uint32:
		return uint64(v.(uint32)), nil
	case uint64:
		return v.(uint64), nil
	default:
		return 0, errors.New("unknown type")
	}
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

func WriteByte(buf *bytes.Buffer, v interface{}) error {
	switch v.(type) {
	case uint16:
		buf.WriteByte(0xFD)
	case uint32:
		buf.WriteByte(0xFE)
	case uint64:
		buf.WriteByte(0xFF)
	}
	err := binary.Write(buf, binary.BigEndian, v)
	if err != nil {
		return err
	}
	return nil
}

func (this *tlv) Parse(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty buffer")
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

func (this *tlv) Dump() ([]byte, error) {
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
		return nil, errors.New("value and children cannot both exist")
	}
	if len(this.Value) == 0 {
		for i := range this.Children {
			b, err := this.Children[i].Dump()
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

func ReadList(raw []byte) ([]*tlv, error) {
	ret := []*tlv{}
	var err error
	for len(raw) != 0 {
		v := new(tlv)
		raw, err = v.Parse(raw)
		if err != nil {
			return nil, err
		}
		ret = append(ret, v)
	}
	return ret, nil
}
