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

// 5
type Interest struct {
	Name      [][]byte  `tlv:"7,8"`
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
	Name           [][]byte      `tlv:"7,8"`
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
	Name   [][]byte `tlv:"7,8,-"`
	Digest []byte   `tlv:"29,-"`
}

func nameFromString(s string) (b [][]byte) {
	if len(s) == 0 {
		return
	}
	for _, c := range strings.Split(strings.Trim(s, "/"), "/") {
		b = append(b, []byte(c))
	}
	return
}

func nameToString(b [][]byte) (s string) {
	for _, c := range b {
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
		Name:  nameFromString(name),
		Nonce: newNonce(),
	}
}

func (this *Interest) Print() {
	spew.Dump(*this)
}

func (this *Interest) Encode() (raw []byte, err error) {
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

func (this *Data) Encode() (raw []byte, err error) {
	digest, err := tlv.Hash(this, sha256.New(), []int{0, 1, 2, 3})
	if err != nil {
		return
	}
	switch this.SignatureInfo.SignatureType {
	case SignatureTypeSha256:
		this.SignatureValue = digest
	case SignatureTypeSha256Rsa:
		this.SignatureValue, err = signRSA(digest)
		if err != nil {
			return
		}
	}
	raw, err = tlv.Marshal(this, 6)
	return
}

func (this *Data) Decode(raw []byte) error {
	digest, err := tlv.Hash(this, sha256.New(), []int{0, 1, 2, 3})
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
	return tlv.Unmarshal(raw, this, 6)
}
