package ndn

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/davecgh/go-spew/spew"
	"github.com/taylorchu/tlv"
	"reflect"
	"strings"
)

type Name struct {
	Components [][]byte `tlv:"8"`
}

// 5
type Interest struct {
	Name      Name      `tlv:"7"`
	Selectors Selectors `tlv:"9,-"`
	Nonce     []byte    `tlv:"10"`
	Scope     uint64    `tlv:"11,-"`
	LifeTime  uint64    `tlv:"12,-"`
}

type Selectors struct {
	MinSuffixComponents       uint64     `tlv:"13,-"`
	MaxSuffixComponents       uint64     `tlv:"14,-"`
	PublisherPublicKeyLocator KeyLocator `tlv:"15,-"`
	Exclude                   []byte     `tlv:"16,-"`
	ChildSelector             uint64     `tlv:"17,-"`
	MustBeFresh               bool       `tlv:"18,-"`
}

// 6
type Data struct {
	Name           Name          `tlv:"7"`
	MetaInfo       MetaInfo      `tlv:"20"`
	Content        []byte        `tlv:"21"`
	SignatureInfo  SignatureInfo `tlv:"22"`
	SignatureValue []byte        `tlv:"23"`
}

type MetaInfo struct {
	ContentType     uint64       `tlv:"24,-"`
	FreshnessPeriod uint64       `tlv:"25,-"`
	FinalBlockId    FinalBlockId `tlv:"26,-"`
}

type FinalBlockId struct {
	NameComponent []byte `tlv:"8"`
}

type SignatureInfo struct {
	SignatureType uint64     `tlv:"27"`
	KeyLocator    KeyLocator `tlv:"28,-"`
}

const (
	SignatureTypeSha256    uint64 = 0
	SignatureTypeSha256Rsa        = 1
)

type KeyLocator struct {
	Name   Name   `tlv:"7,-"`
	Digest []byte `tlv:"29,-"`
}

func nameFromString(s string) (name Name) {
	if len(s) == 0 {
		return
	}
	for _, c := range strings.Split(strings.Trim(s, "/"), "/") {
		name.Components = append(name.Components, []byte(c))
	}
	return
}

func nameToString(name Name) (s string) {
	for _, c := range name.Components {
		s += "/" + string(c)
	}
	return
}

func newNonce() []byte {
	b := make([]byte, 4)
	rand.Read(b)
	return b
}

func NewInterest(name string) *Interest {
	return &Interest{
		Name: nameFromString(name),
	}
}

func (this *Interest) Print() {
	spew.Dump(*this)
}

func (this *Interest) Encode() (raw []byte, err error) {
	this.Nonce = newNonce()
	raw, err = tlv.Marshal(this, 5)
	return
}

func (this *Interest) Decode(raw []byte) error {
	return tlv.Unmarshal(raw, this, 5)
}

func NewData(name string) *Data {
	return &Data{
		Name: nameFromString(name),
	}
}

func (this *Data) Print() {
	spew.Dump(*this)
}

func newSha256(v interface{}) (digest []byte, err error) {
	value := reflect.ValueOf(v)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	h := sha256.New()
	for i := 0; i < value.NumField()-1; i++ {
		var t uint64
		t, err = tlv.Type(value, i)
		if err != nil {
			return
		}
		var b []byte
		b, err = tlv.Marshal(value.Field(i).Interface(), t)
		if err != nil {
			return
		}
		h.Write(b)
	}
	digest = h.Sum(nil)
	return
}

func (this *Data) Encode() (raw []byte, err error) {
	digest, err := newSha256(this)
	if err != nil {
		return
	}
	switch this.SignatureInfo.SignatureType {
	case SignatureTypeSha256:
		this.SignatureValue = digest
	case SignatureTypeSha256Rsa:
		this.SignatureInfo.KeyLocator.Name = SignKey.LocatorName()
		this.SignatureValue, err = signRSA(digest)
		if err != nil {
			return
		}
	}
	raw, err = tlv.Marshal(this, 6)
	return
}

func (this *Data) Decode(raw []byte) error {
	err := tlv.Unmarshal(raw, this, 6)
	if err != nil {
		return err
	}
	digest, err := newSha256(this)
	if err != nil {
		return err
	}
	switch this.SignatureInfo.SignatureType {
	case SignatureTypeSha256:
		if !bytes.Equal(this.SignatureValue, digest) {
			return errors.New("cannot verify sha256")
		}
	case SignatureTypeSha256Rsa:
		// TODO: enable rsa
	}
	return nil
}
