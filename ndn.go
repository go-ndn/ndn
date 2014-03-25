package ndn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	//"fmt"
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
	for _, part := range strings.Split(s, "/") {
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
		err = binary.Write(buf, binary.BigEndian, uint64(v))
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
	buf := bytes.NewReader(raw)
	switch len(raw) {
	case 8:
		var v64 uint64
		err = binary.Read(buf, binary.BigEndian, &v64)
		if err != nil {
			return
		}
		v = uint64(v64)
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

type Selectors struct {
	MinSuffixComponents       uint64
	MaxSuffixComponents       uint64
	PublisherPublicKeyLocator string
	Exclude                   []string
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
	maxSuffixComponents := NewTLV(MAX_SUFFIX_COMPONENTS)
	maxSuffixComponents.Value, err = encodeNonNeg(this.Selectors.MaxSuffixComponents)
	selectors.Add(maxSuffixComponents)

	// PublisherPublicKeyLocator
	publisherPublicKeyLocator := NewTLV(PUBLISHER_PUBLICKEY_LOCATOR)
	publisherPublicKeyLocator.Add(uriDecode(this.Selectors.PublisherPublicKeyLocator))
	selectors.Add(publisherPublicKeyLocator)

	// FIXME: EXCLUDE

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
					if len(cc.Children) != 1 || cc.Children[0].Type != NAME {
						return errors.New(nodeType(PUBLISHER_PUBLICKEY_LOCATOR))
					}
					this.Selectors.PublisherPublicKeyLocator = uriEncode(cc.Children[0])
				case EXCLUDE:
					// FIXME
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

type MetaInfo struct {
	ContentType     uint64
	FreshnessPeriod uint64
}

type Signature struct {
	KeyLocator    string
	Witness       []byte
	SignatureBits []byte
}

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
	FreshnessPeriod := NewTLV(FRESHNESS_PERIOD)
	FreshnessPeriod.Value, err = encodeNonNeg(this.MetaInfo.FreshnessPeriod)
	if err != nil {
		return
	}
	metaInfo.Add(FreshnessPeriod)

	data.Add(metaInfo)

	// content
	content := NewTLV(CONTENT)
	content.Value = this.Content
	data.Add(content)

	// signature
	signature := NewTLV(SIGNATURE)
	if len(this.Signature.KeyLocator) == 0 && len(this.Signature.Witness) == 0 {
		// DIGEST_SHA256
		digest := NewTLV(DIGEST_SHA256)
		digest.Value = this.Signature.SignatureBits
		signature.Add(digest)
	} else {
		// SIGNATURE_SHA256_WITH_RSA
		rsa := NewTLV(SIGNATURE_SHA256_WITH_RSA)
		// KEY_LOCATOR
		keyLocator := NewTLV(KEY_LOCATOR)
		certificateName := NewTLV(CERTIFICATE_NAME)
		certificateName.Add(uriDecode(this.Signature.KeyLocator))
		keyLocator.Add(certificateName)
		rsa.Add(keyLocator)

		if len(this.Signature.Witness) != 0 {
			// SIGNATURE_SHA256_WITH_RSA_AND_MERKLE
			rsa.Type = SIGNATURE_SHA256_WITH_RSA_AND_MERKLE

			Witness := NewTLV(WITNESS)
			Witness.Value = this.Signature.Witness
			rsa.Add(Witness)
		}

		// signature bits
		signatureBits := NewTLV(SIGNATURE_BITS)
		signatureBits.Value = this.Signature.SignatureBits
		rsa.Add(signatureBits)

		signature.Add(rsa)
	}
	data.Add(signature)

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
				}
			}
		case CONTENT:
			this.Content = c.Value
		case SIGNATURE:
			for _, cc := range c.Children {
				switch cc.Type {
				case DIGEST_SHA256:
					this.Signature.SignatureBits = cc.Value
				case SIGNATURE_SHA256_WITH_RSA:
					fallthrough
				case SIGNATURE_SHA256_WITH_RSA_AND_MERKLE:
					for _, ccc := range cc.Children {
						switch ccc.Type {
						case KEY_LOCATOR:
							if len(ccc.Children) != 1 ||
								ccc.Children[0].Type != CERTIFICATE_NAME ||
								len(ccc.Children[0].Children) != 1 ||
								ccc.Children[0].Children[0].Type != NAME {
								return errors.New(nodeType(CERTIFICATE_NAME))
							}
							this.Signature.KeyLocator = uriEncode(ccc.Children[0].Children[0])
						case SIGNATURE_BITS:
							this.Signature.SignatureBits = ccc.Value
						case WITNESS:
							this.Signature.Witness = ccc.Value
						}
					}
				}
			}
		}
	}
	return nil
}
