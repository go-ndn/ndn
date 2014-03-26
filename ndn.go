package ndn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"sort"
	"strings"
	//"fmt"
	"crypto/rand"
)

/*
	Define high-level NDN struct
	(other file should not be used)
*/

func uriEncode(tlv *TLV) string {
	s := []string{}
	for _, c := range tlv.Children {
		s = append(s, string(c.Value))
	}
	return strings.Join(s, "/")
}

func uriDecode(s string) *TLV {
	tlv := NewTLV(NAME)
	parts := strings.Split(strings.TrimLeft(s, "/"), "/")
	sort.Strings(parts)
	for _, part := range parts {
		c := NewTLV(NAME_COMPONENT)
		c.Value = []byte(part)
		tlv.Add(c)
	}
	return tlv
}

func encodeNonNeg(v uint64) (raw []byte, err error) {
	buf := new(bytes.Buffer)
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
	raw = buf.Bytes()
	return
}

func decodeNonNeg(raw []byte) (v uint64, err error) {
	buf := bytes.NewBuffer(raw)
	switch len(raw) {
	case 8:
		var v64 uint64
		err = binary.Read(buf, binary.BigEndian, &v64)
		if err != nil {
			return
		}
		v = v64
	case 4:
		var v32 uint32
		err = binary.Read(buf, binary.BigEndian, &v32)
		if err != nil {
			return
		}
		v = uint64(v32)
	case 2:
		var v16 uint16
		err = binary.Read(buf, binary.BigEndian, &v16)
		if err != nil {
			return
		}
		v = uint64(v16)
	case 1:
		var v8 uint8
		err = binary.Read(buf, binary.BigEndian, &v8)
		if err != nil {
			return
		}
		v = uint64(v8)
	}
	return
}

func NewTLV(t uint64) *TLV {
	return &TLV{Type: t}
}

type Interest struct {
	Name             string
	Selectors        Selectors
	Nonce            []byte
	Scope            uint64
	InterestLifeTime uint64
}

func NewNonce() []byte {
	b := make([]byte, 4)
	rand.Read(b)
	return b
}

func NewInterest(name string) *Interest {
	return &Interest{
		Name:             name,
		Nonce:            NewNonce(),
		InterestLifeTime: 4000,
	}
}

type Selectors struct {
	MinSuffixComponents       uint64
	MaxSuffixComponents       uint64
	PublisherPublicKeyLocator *TLV // only child
	Exclude                   *TLV // itself
	ChildSelector             uint64
	MustBeFresh               bool
}

func (this *Interest) Encode() (raw []byte, err error) {
	interest := NewTLV(INTEREST)

	// name
	interest.Add(uriDecode(this.Name))

	// selector
	selectors := NewTLV(SELECTORS)
	// MinSuffixComponents
	minSuffixComponents := NewTLV(MIN_SUFFIX_COMPONENTS)
	minSuffixComponents.Value, err = encodeNonNeg(this.Selectors.MinSuffixComponents)
	selectors.Add(minSuffixComponents)

	// MaxSuffixComponents
	if this.Selectors.MaxSuffixComponents != 0 {
		maxSuffixComponents := NewTLV(MAX_SUFFIX_COMPONENTS)
		maxSuffixComponents.Value, err = encodeNonNeg(this.Selectors.MaxSuffixComponents)
		selectors.Add(maxSuffixComponents)
	}

	// PublisherPublicKeyLocator
	if this.Selectors.PublisherPublicKeyLocator != nil {
		publisherPublicKeyLocator := NewTLV(KEY_LOCATOR)
		publisherPublicKeyLocator.Add(this.Selectors.PublisherPublicKeyLocator)
		selectors.Add(publisherPublicKeyLocator)
	}

	// EXCLUDE
	if this.Selectors.Exclude != nil {
		selectors.Add(this.Selectors.Exclude)
	}

	// ChildSelector
	childSelector := NewTLV(CHILD_SELECTOR)
	childSelector.Value, err = encodeNonNeg(this.Selectors.ChildSelector)
	if err != nil {
		return
	}
	selectors.Add(childSelector)

	if this.Selectors.MustBeFresh {
		mustBeFresh := NewTLV(MUST_BE_FRESH)
		selectors.Add(mustBeFresh)
	}

	interest.Add(selectors)

	// nonce
	nonce := NewTLV(NONCE)
	nonce.Value = this.Nonce
	interest.Add(nonce)

	// scope
	scope := NewTLV(SCOPE)
	scope.Value, err = encodeNonNeg(this.Scope)
	if err != nil {
		return
	}
	interest.Add(scope)

	// interest lifetime
	interestLifeTime := NewTLV(INTEREST_LIFETIME)
	interestLifeTime.Value, err = encodeNonNeg(this.InterestLifeTime)
	if err != nil {
		return
	}
	interest.Add(interestLifeTime)

	// final encode
	raw, err = interest.Encode()
	return
}

func (this *Interest) Decode(raw []byte) error {
	tlv, err := DecodeInterest(raw)
	if err != nil {
		return err
	}
	for _, c := range tlv.Children {
		switch c.Type {
		case NAME:
			this.Name = uriEncode(c)
		case SELECTORS:
			for _, cc := range c.Children {
				switch cc.Type {
				case MIN_SUFFIX_COMPONENTS:
					this.Selectors.MinSuffixComponents, err = decodeNonNeg(cc.Value)
					if err != nil {
						return err
					}
				case MAX_SUFFIX_COMPONENTS:
					this.Selectors.MaxSuffixComponents, err = decodeNonNeg(cc.Value)
					if err != nil {
						return err
					}
				case PUBLISHER_PUBLICKEY_LOCATOR:
					if len(cc.Children) != 1 {
						return errors.New(nodeType(PUBLISHER_PUBLICKEY_LOCATOR))
					}
					this.Selectors.PublisherPublicKeyLocator = cc.Children[0]
				case EXCLUDE:
					this.Selectors.Exclude = cc
				case CHILD_SELECTOR:
					this.Selectors.ChildSelector, err = decodeNonNeg(cc.Value)
					if err != nil {
						return err
					}
				case MUST_BE_FRESH:
					this.Selectors.MustBeFresh = true
				}
			}
		case NONCE:
			this.Nonce = c.Value
		case SCOPE:
			this.Scope, err = decodeNonNeg(c.Value)
			if err != nil {
				return err
			}
		case INTEREST_LIFETIME:
			this.InterestLifeTime, err = decodeNonNeg(c.Value)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type Data struct {
	Name      string
	MetaInfo  MetaInfo
	Content   []byte
	Signature Signature
}

func NewData(name string) *Data {
	return &Data{
		Name: name,
	}
}

type MetaInfo struct {
	ContentType     uint64
	FreshnessPeriod uint64
	FinalBlockId    string
}

const (
	CONTENT_TYPE_BLOB uint64 = 0
	CONTENT_TYPE_LINK        = 1
	CONTENT_TYPE_KEY         = 2
	CONTENT_TYPE_NACK        = 3 // TBD
)

type Signature struct {
	Type  uint64
	Info  []*TLV
	Value []byte
}

const (
	SIGNATURE_TYPE_DIGEST_SHA_256             uint64 = 0
	SIGNATURE_TYPE_SIGNATURE_SHA_256_WITH_RSA        = 1
)

func (this *Data) Encode() (raw []byte, err error) {
	data := NewTLV(DATA)

	// name
	data.Add(uriDecode(this.Name))

	// meta info
	metaInfo := NewTLV(META_INFO)

	// ContentType
	contentType := NewTLV(CONTENT_TYPE)
	contentType.Value, err = encodeNonNeg(this.MetaInfo.ContentType)
	if err != nil {
		return
	}
	metaInfo.Add(contentType)

	// FreshnessPeriod
	freshnessPeriod := NewTLV(FRESHNESS_PERIOD)
	freshnessPeriod.Value, err = encodeNonNeg(this.MetaInfo.FreshnessPeriod)
	if err != nil {
		return
	}
	metaInfo.Add(freshnessPeriod)

	// FinalBlockId
	finalBlockId := NewTLV(FINAL_BLOCK_ID)
	comp := NewTLV(NAME_COMPONENT)
	comp.Value = []byte(this.MetaInfo.FinalBlockId)
	finalBlockId.Add(comp)
	metaInfo.Add(finalBlockId)

	data.Add(metaInfo)

	// content
	content := NewTLV(CONTENT)
	content.Value = this.Content
	data.Add(content)

	// signature info
	signatureInfo := NewTLV(SIGNATURE_INFO)
	// signature type
	signatureType := NewTLV(SIGNATURE_TYPE)
	signatureType.Value, err = encodeNonNeg(this.Signature.Type)
	if err != nil {
		return
	}
	signatureInfo.Add(signatureType)
	// add other info
	for _, c := range this.Signature.Info {
		signatureInfo.Add(c)
	}
	data.Add(signatureInfo)

	// signature value
	signatureValue := NewTLV(SIGNATURE_VALUE)
	signatureValue.Value = this.Signature.Value
	data.Add(signatureValue)

	// final encode
	raw, err = data.Encode()
	return
}

func (this *Data) Decode(raw []byte) error {
	tlv, err := DecodeData(raw)
	if err != nil {
		return err
	}
	for _, c := range tlv.Children {
		switch c.Type {
		case NAME:
			this.Name = uriEncode(c)
		case META_INFO:
			for _, cc := range c.Children {
				switch cc.Type {
				case CONTENT_TYPE:
					this.MetaInfo.ContentType, err = decodeNonNeg(cc.Value)
					if err != nil {
						return err
					}
				case FRESHNESS_PERIOD:
					this.MetaInfo.FreshnessPeriod, err = decodeNonNeg(cc.Value)
					if err != nil {
						return err
					}
				case FINAL_BLOCK_ID:
					if len(cc.Children) != 1 ||
						cc.Children[0].Type != NAME_COMPONENT {
						return errors.New(nodeType(FINAL_BLOCK_ID))
					}
					this.MetaInfo.FinalBlockId = string(cc.Children[0].Value)
				}
			}
		case CONTENT:
			this.Content = c.Value
		case SIGNATURE_INFO:
			for _, cc := range c.Children {
				switch cc.Type {
				case SIGNATURE_TYPE:
					this.Signature.Type, err = decodeNonNeg(cc.Value)
					if err != nil {
						return err
					}
				default:
					this.Signature.Info = append(this.Signature.Info, cc)
				}
			}
		case SIGNATURE_VALUE:
			this.Signature.Value = c.Value
		}
	}
	return nil
}
