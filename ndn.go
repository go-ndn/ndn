package ndn

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/davecgh/go-spew/spew"
	"github.com/taylorchu/tlv"
	"strings"
)

func Print(i interface{}) {
	spew.Dump(i)
}

type Name struct {
	Components [][]byte `tlv:"8"`
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
	NameComponent []byte `tlv:"8"`
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

func (this *Name) Set(s string) {
	if len(s) == 0 {
		return
	}
	for _, c := range strings.Split(strings.Trim(s, "/"), "/") {
		this.Components = append(this.Components, []byte(c))
	}
	return
}

func (this Name) String() (s string) {
	for _, c := range this.Components {
		s += "/" + string(c)
	}
	return
}

func newNonce() []byte {
	b := make([]byte, 4)
	rand.Read(b)
	return b
}

func NewInterest(name string) (i *Interest) {
	i = new(Interest)
	i.Name.Set(name)
	return
}

func (this *Interest) WriteTo(w tlv.Writer) error {
	this.Nonce = newNonce()
	return tlv.Marshal(w, this, 5)
}

func (this *Interest) ReadFrom(r tlv.PeekReader) error {
	return tlv.Unmarshal(r, this, 5)
}

func NewData(name string) (d *Data) {
	d = new(Data)
	d.Name.Set(name)
	return
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
	switch this.SignatureInfo.SignatureType {
	case SignatureTypeSha256:
		this.SignatureValue = digest
	default:
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
			err = errors.New("cannot verify sha256")
			return
		}
	case SignatureTypeSha256WithRsa:
		// TODO: enable rsa
	}
	return
}
