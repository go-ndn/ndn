package ndn

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/taylorchu/tlv"
	"io"
	"math"
	"net/url"
	"strings"
)

func Print(i ...interface{}) {
	spew.Dump(i...)
}

type Component []byte

type Name struct {
	Components []Component `tlv:"8"`
}

// 5
type Interest struct {
	Name      Name      `tlv:"7"`
	Selectors Selectors `tlv:"9?"`
	Nonce     []byte    `tlv:"10"`
	Scope     uint64    `tlv:"11?"`
	LifeTime  uint64    `tlv:"12?"`
}

type Selectors struct {
	MinSuffixComponents       uint64     `tlv:"13?"`
	MaxSuffixComponents       uint64     `tlv:"14?"`
	PublisherPublicKeyLocator KeyLocator `tlv:"15?"`
	Exclude                   []byte     `tlv:"16?"`
	ChildSelector             uint64     `tlv:"17?"`
	MustBeFresh               bool       `tlv:"18?"`
}

// 6
type Data struct {
	Name           Name          `tlv:"7"`
	MetaInfo       MetaInfo      `tlv:"20"`
	Content        []byte        `tlv:"21"`
	SignatureInfo  SignatureInfo `tlv:"22"`
	SignatureValue []byte        `tlv:"23*"`
}

type MetaInfo struct {
	ContentType     uint64       `tlv:"24?"`
	FreshnessPeriod uint64       `tlv:"25?"`
	FinalBlockId    FinalBlockId `tlv:"26?"`
}

type FinalBlockId struct {
	Component Component `tlv:"8"`
}

type SignatureInfo struct {
	SignatureType uint64     `tlv:"27"`
	KeyLocator    KeyLocator `tlv:"28?"`
}

const (
	SignatureTypeSha256          uint64 = 0
	SignatureTypeSha256WithRsa          = 1
	SignatureTypeSha256WithEcdsa        = 2
)

type KeyLocator struct {
	Name   Name   `tlv:"7?"`
	Digest []byte `tlv:"29?"`
}

type Marker uint8

const (
	Segment    Marker = 0x00
	ByteOffset        = 0xFB
	Version           = 0xFD
	Timestamp         = 0xFC
	Sequence          = 0xFE
)

func NewName(s string) (n Name) {
	for _, c := range strings.Split(strings.Trim(s, "/"), "/") {
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
	for _, c := range this.Components {
		name += "/" + url.QueryEscape(string(c))
	}
	return
}

func newNonce() []byte {
	b := make([]byte, 4)
	rand.Read(b)
	return b
}

func (this *Interest) WriteTo(w tlv.Writer) error {
	this.Nonce = newNonce()
	if this.LifeTime == 0 {
		this.LifeTime = 4000
	}
	return tlv.Marshal(w, this, 5)
}

func (this *Interest) ReadFrom(r tlv.PeekReader) error {
	return tlv.Unmarshal(r, this, 5)
}

func newSha256(v interface{}) (digest []byte, err error) {
	h := sha256.New()
	err = tlv.Data(h, v)
	if err != nil {
		return
	}
	digest = h.Sum(nil)
	return
}

func (this *Data) WriteTo(w tlv.Writer) (err error) {
	digest, err := newSha256(this)
	if err != nil {
		return
	}
	sigType := SignKey.SignatureType()
	switch sigType {
	case SignatureTypeSha256:
		this.SignatureValue = digest
	default:
		this.SignatureInfo.SignatureType = sigType
		this.SignatureInfo.KeyLocator.Name = SignKey.LocatorName()
		this.SignatureValue, err = SignKey.Sign(digest)
		if err != nil {
			return
		}
	}
	err = tlv.Marshal(w, this, 6)
	return
}

func (this *Data) ReadFrom(r tlv.PeekReader) (err error) {
	err = tlv.Unmarshal(r, this, 6)
	if err != nil {
		return
	}
	digest, err := newSha256(this)
	if err != nil {
		return
	}
	switch this.SignatureInfo.SignatureType {
	case SignatureTypeSha256:
		if !bytes.Equal(this.SignatureValue, digest) {
			err = fmt.Errorf("cannot verify sha256")
			return
		}
	case SignatureTypeSha256WithRsa:
		// TODO: enable rsa
	}
	return
}
