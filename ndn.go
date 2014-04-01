package ndn

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"strings"
)

/*
	Define high-level NDN struct
	(other file should not be used)
*/

func nameEncode(parts [][]byte) TLV {
	tlv := NewTLV(NAME)
	for _, part := range parts {
		c := NewTLV(NAME_COMPONENT)
		c.Value = part
		tlv.Add(c)
	}
	return tlv
}

func nameDecode(tlv TLV) (b [][]byte) {
	for _, c := range tlv.Children {
		b = append(b, c.Value)
	}
	return
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

func NewTLV(t uint64) TLV {
	return TLV{Type: t}
}

type Interest struct {
	Name             [][]byte
	Selectors        Selectors
	Nonce            []byte
	Scope            uint64
	InterestLifeTime uint64
}

const (
	SCOPE_LOCAL_NDN_DAEMON uint64 = 0
	SCOPE_LOCAL_APP               = 1
	SCOPE_NEXT_NODE               = 2
)

func newNonce() []byte {
	b := make([]byte, 4)
	rand.Read(b)
	return b
}

func NewInterest(name string) *Interest {
	return &Interest{
		Name:             nameFromString(name),
		Nonce:            newNonce(),
		InterestLifeTime: 4000,
	}
}

type Selectors struct {
	MinSuffixComponents       uint64
	MaxSuffixComponents       uint64
	PublisherPublicKeyLocator TLV   // Name or KeyLocatorDigest
	Exclude                   []TLV // List of Any or NameComponent TLV
	ChildSelector             uint64
	MustBeFresh               bool
}

const (
	CHILD_SELECTOR_FIRST uint64 = 0 // leftmost
	CHILD_SELECTOR_LAST         = 1 // rightmost
)

func (this *Interest) Encode() (raw []byte, err error) {
	interest := NewTLV(INTEREST)

	// name
	interest.Add(nameEncode(this.Name))

	// selector
	selectors := NewTLV(SELECTORS)
	emptySelectors := true
	// MinSuffixComponents
	if this.Selectors.MinSuffixComponents != 0 {
		emptySelectors = false
		minSuffixComponents := NewTLV(MIN_SUFFIX_COMPONENTS)
		minSuffixComponents.Value, err = encodeNonNeg(this.Selectors.MinSuffixComponents)
		selectors.Add(minSuffixComponents)
	}

	// MaxSuffixComponents
	if this.Selectors.MaxSuffixComponents != 0 {
		emptySelectors = false
		maxSuffixComponents := NewTLV(MAX_SUFFIX_COMPONENTS)
		maxSuffixComponents.Value, err = encodeNonNeg(this.Selectors.MaxSuffixComponents)
		selectors.Add(maxSuffixComponents)
	}

	// PublisherPublicKeyLocator
	if this.Selectors.PublisherPublicKeyLocator.Type != 0 {
		emptySelectors = false
		publisherPublicKeyLocator := NewTLV(PUBLISHER_PUBLICKEY_LOCATOR)
		publisherPublicKeyLocator.Add(this.Selectors.PublisherPublicKeyLocator)
		selectors.Add(publisherPublicKeyLocator)
	}

	// EXCLUDE
	if len(this.Selectors.Exclude) != 0 {
		emptySelectors = false
		exclude := NewTLV(EXCLUDE)
		for _, c := range this.Selectors.Exclude {
			exclude.Add(c)
		}
		selectors.Add(exclude)
	}

	// ChildSelector
	if this.Selectors.ChildSelector != 0 {
		emptySelectors = false
		childSelector := NewTLV(CHILD_SELECTOR)
		childSelector.Value, err = encodeNonNeg(this.Selectors.ChildSelector)
		if err != nil {
			return
		}
		selectors.Add(childSelector)
	}

	if this.Selectors.MustBeFresh {
		emptySelectors = false
		mustBeFresh := NewTLV(MUST_BE_FRESH)
		selectors.Add(mustBeFresh)
	}

	if !emptySelectors {
		interest.Add(selectors)
	}

	// nonce
	nonce := NewTLV(NONCE)
	nonce.Value = this.Nonce
	interest.Add(nonce)

	// scope
	if this.Scope != 0 {
		scope := NewTLV(SCOPE)
		scope.Value, err = encodeNonNeg(this.Scope)
		if err != nil {
			return
		}
		interest.Add(scope)
	}

	// interest lifetime
	if this.InterestLifeTime != 0 {
		interestLifeTime := NewTLV(INTEREST_LIFETIME)
		interestLifeTime.Value, err = encodeNonNeg(this.InterestLifeTime)
		if err != nil {
			return
		}
		interest.Add(interestLifeTime)
	}
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
			this.Name = nameDecode(c)
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
						return errors.New(typeString(PUBLISHER_PUBLICKEY_LOCATOR))
					}
					this.Selectors.PublisherPublicKeyLocator = cc.Children[0]
				case EXCLUDE:
					for _, ccc := range cc.Children {
						switch ccc.Type {
						case ANY:
							fallthrough
						case NAME_COMPONENT:
							this.Selectors.Exclude = append(this.Selectors.Exclude, ccc)
						}
					}
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
	Name      [][]byte
	MetaInfo  MetaInfo
	Content   []byte
	Signature Signature
}

func NewData(name string) *Data {
	return &Data{
		Name: nameFromString(name),
	}
}

type MetaInfo struct {
	ContentType     uint64
	FreshnessPeriod uint64
	FinalBlockId    []byte
}

const (
	CONTENT_TYPE_BLOB uint64 = 0
	CONTENT_TYPE_LINK        = 1
	CONTENT_TYPE_KEY         = 2
	CONTENT_TYPE_NACK        = 3 // TBD
)

type Signature struct {
	Type  uint64
	Info  []TLV // List of SignatureInfo TLVs
	Value []byte
}

const (
	SIGNATURE_TYPE_DIGEST_SHA_256             uint64 = 0
	SIGNATURE_TYPE_SIGNATURE_SHA_256_WITH_RSA        = 1
)

func (this *Data) Encode() (raw []byte, err error) {
	data := NewTLV(DATA)

	// name
	name := nameEncode(this.Name)
	data.Add(name)

	// meta info
	metaInfo := NewTLV(META_INFO)

	// ContentType
	if this.MetaInfo.ContentType != 0 {
		contentType := NewTLV(CONTENT_TYPE)
		contentType.Value, err = encodeNonNeg(this.MetaInfo.ContentType)
		if err != nil {
			return
		}
		metaInfo.Add(contentType)
	}

	// FreshnessPeriod
	if this.MetaInfo.FreshnessPeriod != 0 {
		freshnessPeriod := NewTLV(FRESHNESS_PERIOD)
		freshnessPeriod.Value, err = encodeNonNeg(this.MetaInfo.FreshnessPeriod)
		if err != nil {
			return
		}
		metaInfo.Add(freshnessPeriod)
	}

	// FinalBlockId
	if len(this.MetaInfo.FinalBlockId) != 0 {
		finalBlockId := NewTLV(FINAL_BLOCK_ID)
		comp := NewTLV(NAME_COMPONENT)
		comp.Value = this.MetaInfo.FinalBlockId
		finalBlockId.Add(comp)
		metaInfo.Add(finalBlockId)
	}

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
	// add empty keyLocator for rsa
	if this.Signature.Type == SIGNATURE_TYPE_SIGNATURE_SHA_256_WITH_RSA && len(this.Signature.Info) == 0 {
		keyLocator := NewTLV(KEY_LOCATOR)
		keyLocator.Add(nameEncode([][]byte{
			[]byte("testing"),
			[]byte("KEY"),
			[]byte("pubkey"),
			[]byte("ID-CERT"),
		}))
		signatureInfo.Add(keyLocator)
	}
	data.Add(signatureInfo)

	// signature value
	signatureValue := NewTLV(SIGNATURE_VALUE)
	if len(this.Signature.Value) == 0 {
		switch this.Signature.Type {
		case SIGNATURE_TYPE_DIGEST_SHA_256:
			signatureValue.Value, err = newSHA256([]TLV{name, metaInfo, content, signatureInfo})
			if err != nil {
				return
			}
		case SIGNATURE_TYPE_SIGNATURE_SHA_256_WITH_RSA:
			signatureValue.Value, err = signRSA([]TLV{name, metaInfo, content, signatureInfo})
			if err != nil {
				return
			}
		}
	} else {
		signatureValue.Value = this.Signature.Value
	}
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
			this.Name = nameDecode(c)
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
						return errors.New(typeString(FINAL_BLOCK_ID))
					}
					this.MetaInfo.FinalBlockId = cc.Children[0].Value
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
			switch this.Signature.Type {
			case SIGNATURE_TYPE_DIGEST_SHA_256:
				sum, err := newSHA256(tlv.Children[:4])
				if err != nil {
					return err
				}
				if !bytes.Equal(sum, c.Value) {
					return errors.New(INVALID_SHA_256)
				}
			case SIGNATURE_TYPE_SIGNATURE_SHA_256_WITH_RSA:
				// TODO: enable rsa
				// if !verifyRSA(tlv.Children[:4], c.Value) {
				// 	return errors.New(INVALID_RSA)
				// }
			}
			this.Signature.Value = c.Value
		}
	}
	return nil
}

func newSHA256(l []TLV) (sum []byte, err error) {
	buf := new(bytes.Buffer)
	for _, c := range l {
		var b []byte
		b, err = c.Encode()
		if err != nil {
			return
		}
		buf.Write(b)
	}
	sha := sha256.Sum256(buf.Bytes())
	sum = sha[:]
	return
}
