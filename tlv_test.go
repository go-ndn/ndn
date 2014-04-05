package ndn

import (
	"bytes"
	//"fmt"
	"testing"
)

func TestReadByte(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77})
	r, _ := readByte(buf)
	if r != 4822678189205111 {
		t.Errorf("expected %v, got %v", 4822678189205111, r)
		return
	}
}

func TestWriteByte(t *testing.T) {
	buf := new(bytes.Buffer)
	writeByte(buf, 4822678189205111)
	if !bytes.Equal(buf.Bytes(), []byte{0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}) {
		t.Errorf("expected %v, got %v", []byte{0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}, buf.Bytes())
		return
	}
}

func TestDecode(t *testing.T) {
	v := TLV{}
	r, _ := v.Decode([]byte{0xF0, 0x01, 0x01, 0x01})
	if v.Type != 240 {
		t.Errorf("expected %v, got %v", 240, v.Type)
		return
	}

	if len(r) != 1 || r[0] != 1 {
		t.Errorf("expected %v, got %v", 1, r[0])
		return
	}
	r, _ = v.Decode([]byte{0xF0, 0x2, 0x01, 0x02})
	if v.Value[0] != 1 {
		t.Errorf("expected %v, got %v", 1, v.Value[0])
		return
	}
	if v.Value[1] != 2 {
		t.Errorf("expected %v, got %v", 2, v.Value[1])
		return
	}

	v2 := TLV{}
	r, _ = v2.Decode([]byte{0xFD, 0, 0XFD, 0x00})

	if v2.Type != 253 {
		t.Errorf("expected %v, got %v", 253, v2.Type)
		return
	}
	if v2.Len() != 0 {
		t.Errorf("expected %v, got %v", 0, v2.Len())
		return
	}
}

func TestEncode(t *testing.T) {
	v := TLV{}
	v.Decode([]byte{0xF0, 0x2, 0x01, 0x02})
	if b, _ := v.Encode(); !bytes.Equal(b, []byte{0xF0, 0x2, 0x01, 0x02}) {
		t.Errorf("expected %v, got %v", []byte{0xF0, 0x2, 0x01, 0x02}, b)
		return
	}
}

func TestDecodeSimpleInterest(t *testing.T) {
	name := TLV{}
	name.Type = NAME
	nonce := TLV{}
	nonce.Type = NONCE
	// create selector
	selectors := TLV{}
	selectors.Type = SELECTORS

	max := TLV{}
	max.Type = MAX_SUFFIX_COMPONENTS
	exclude := TLV{}
	exclude.Type = EXCLUDE
	namecomp := TLV{}
	namecomp.Type = NAME_COMPONENT
	exclude.Add(namecomp)
	exclude.Add(namecomp)
	exclude.Add(namecomp)
	exclude.Add(namecomp)

	selectors.Add(max)
	selectors.Add(exclude)

	lifetime := TLV{}
	lifetime.Type = INTEREST_LIFETIME

	interest := TLV{}
	interest.Type = INTEREST
	interest.Add(name)
	interest.Add(selectors)
	interest.Add(nonce)
	interest.Add(lifetime)

	b, err := interest.Encode()
	if err != nil {
		t.Error(err)
		return
	}
	ip, err := match(interestFormat, b)
	if err != nil {
		t.Error(err)
		return
	}
	if len(ip.Children) != len(interest.Children) {
		t.Errorf("expected %v, got %v", len(interest.Children), len(ip.Children))
		return
	}
	b2, _ := ip.Encode()
	if !bytes.Equal(b, b2) {
		t.Errorf("expected %v, got %v", b, b2)
		return
	}
}
