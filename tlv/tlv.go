package tlv

import (
	"bytes"
	"encoding/binary"
	//"log"
)

type tlv struct {
	Type   interface{}
	Length interface{}
	Value  []byte
}

func ToInt(v interface{}) uint64 {
	switch v.(type) {
	case uint8:
		return uint64(v.(uint8))
	case uint16:
		return uint64(v.(uint16))
	case uint32:
		return uint64(v.(uint32))
	case uint64:
		return v.(uint64)
	default:
		panic("unknown type")
	}
}

func ReadByte(buf *bytes.Reader) (result interface{}, offset uint64) {
	b, err := buf.ReadByte()
	if err != nil {
		panic(err)
	}
	switch b {
	case 0xFD:
		var v16 uint16
		err := binary.Read(buf, binary.BigEndian, &v16)
		if err != nil {
			panic(err)
		}
		result = v16
		offset += 2
	case 0xFE:
		var v32 uint32
		err := binary.Read(buf, binary.BigEndian, &v32)
		if err != nil {
			panic(err)
		}
		result = v32
		offset += 4
	case 0xFF:
		var v64 uint64
		err := binary.Read(buf, binary.BigEndian, &v64)
		if err != nil {
			panic(err)
		}
		result = v64
		offset += 8
	default:
		result = uint8(b)
		offset++
	}
	return
}

func WriteByte(buf *bytes.Buffer, v interface{}) {
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
		panic(err)
	}
}

func (this *tlv) Parse(raw []byte) []byte {
	if len(raw) == 0 {
		panic("tlv no bytes to parse")
	}
	buf := bytes.NewReader(raw)
	t, tl := ReadByte(buf)
	this.Type = t
	l, ll := ReadByte(buf)
	this.Length = l
	length := ToInt(l)
	//log.Println(len(raw), tl, ll, l)
	if uint64(len(raw)) > tl+ll {
		this.Value = raw[tl+ll : length]
	}
	return raw[length:]
}

func (this *tlv) Dump() []byte {
	buf := new(bytes.Buffer)
	WriteByte(buf, this.Type)
	WriteByte(buf, this.Length)
	buf.Write(this.Value)
	return buf.Bytes()
}
