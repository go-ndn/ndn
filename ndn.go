// Copyright 2016 Tai-Lin Chu. All rights reserved.
// Use of this source code is governed by GPL2 license.

// Package ndn implements named-data networking.
package ndn

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"hash/crc32"

	"github.com/go-ndn/lpm"
	"github.com/go-ndn/tlv"
)

// Interest carries a name that identifies the desired data.
type Interest struct {
	Name      Name      `tlv:"7"`
	Selectors Selectors `tlv:"9?"`
	Nonce     []byte    `tlv:"10"`
	LifeTime  uint64    `tlv:"12?"`
}

// Selectors are optional elements that further qualify Data that may match the Interest.
// They are used for discovering and selecting the Data that matches best to what the application wants.
type Selectors struct {
	MinComponents             uint64     `tlv:"133?"`
	MaxComponents             uint64     `tlv:"134?"`
	PublisherPublicKeyLocator KeyLocator `tlv:"15?"`
	Exclude                   Exclude    `tlv:"16?"`
	ChildSelector             uint64     `tlv:"17?"`
	MustBeFresh               bool       `tlv:"18?"`
}

// Match does not handle ChildSelector and MustBeFresh.
func (sel *Selectors) Match(d *Data, interestLen int) bool {
	dataLen := d.Name.Len()
	if sel.MinComponents != 0 && sel.MinComponents > uint64(dataLen) {
		return false
	}
	if sel.MaxComponents != 0 && sel.MaxComponents < uint64(dataLen) {
		return false
	}
	if sel.PublisherPublicKeyLocator.Name.Len() != 0 &&
		sel.PublisherPublicKeyLocator.Name.Compare(d.SignatureInfo.KeyLocator.Name) != 0 {
		return false
	}
	if len(sel.PublisherPublicKeyLocator.Digest) != 0 &&
		!bytes.Equal(sel.PublisherPublicKeyLocator.Digest, d.SignatureInfo.KeyLocator.Digest) {
		return false
	}
	if dataLen > interestLen && sel.Exclude.Match(d.Name.Components[interestLen]) {
		return false
	}
	return true
}

// Data represents some arbitrary binary data (held in the Content element) together
// with its Name, some additional bits of information (MetaInfo), and a digital Signature of the other three elements.
type Data struct {
	Name           Name          `tlv:"7"`
	MetaInfo       MetaInfo      `tlv:"20"`
	Content        []byte        `tlv:"21"`
	SignatureInfo  SignatureInfo `tlv:"22"`
	SignatureValue []byte        `tlv:"23*"`
}

// MetaInfo contains information about the data packet itself.
type MetaInfo struct {
	ContentType          uint64       `tlv:"24?"`
	FreshnessPeriod      uint64       `tlv:"25?"`
	FinalBlockID         FinalBlockID `tlv:"26?"`
	CompressionType      uint64       `tlv:"128?"`
	EncryptionType       uint64       `tlv:"129?"`
	EncryptionKeyLocator KeyLocator   `tlv:"130?"`
	EncryptionIV         []byte       `tlv:"131?"`
	CacheHint            uint64       `tlv:"132?"`
}

// FinalBlockID indicates the identifier of the final block in a sequence of fragments.
// It should be present in the final block itself, and may also be present in other
// fragments to provide advanced warning of the end to consumers.
// The value here should be equal to the last explicit Name Component of the final block.
type FinalBlockID struct {
	Component lpm.Component `tlv:"8"`
}

// CompressionType specifies compression algorithm for data packets.
const (
	CompressionTypeNone uint64 = 0
	CompressionTypeGZIP        = 1
)

// CacheHint specifies caching strategy for data packets.
const (
	CacheHintNone    uint64 = 0
	CacheHintNoCache        = 1
)

// EncryptionType specifies encryption algorithm for data packets.
const (
	EncryptionTypeNone       uint64 = 0
	EncryptionTypeAESWithCTR        = 1
)

// SignatureInfo is included in signature calculation and fully describes the signature,
// signature algorithm, and any other relevant information to obtain parent certificate(s),
// such as KeyLocator.
type SignatureInfo struct {
	SignatureType  uint64         `tlv:"27"`
	KeyLocator     KeyLocator     `tlv:"28?"`
	ValidityPeriod ValidityPeriod `tlv:"253?"`
}

// SignatureType specifies signing algorithm for data packets.
const (
	SignatureTypeDigestSHA256    uint64 = 0
	SignatureTypeSHA256WithRSA          = 1
	SignatureTypeDigestCRC32C           = 2
	SignatureTypeSHA256WithECDSA        = 3
	SignatureTypeSHA256WithHMAC         = 4
)

// KeyLocator specifies either Name that points to another Data packet containing
// certificate or public key or KeyDigest to identify the public key within a specific trust model.
type KeyLocator struct {
	Name   Name   `tlv:"7?"`
	Digest []byte `tlv:"29?"`
}

// ISO8601 is the time format for ValidityPeriod.
const (
	ISO8601 = "20060102T150405"
)

// ValidityPeriod specifies a range when the signature is valid.
type ValidityPeriod struct {
	NotBefore string `tlv:"254"`
	NotAfter  string `tlv:"255"`
}

func newNonce() []byte {
	b := make([]byte, 4)
	rand.Read(b)
	return b
}

// WriteTo implements tlv.WriteTo.
//
// Nonce will be populated if it is empty.
func (i *Interest) WriteTo(w tlv.Writer) error {
	if len(i.Nonce) == 0 {
		i.Nonce = newNonce()
	}
	return w.Write(i, 5)
}

// ReadFrom implements tlv.ReadFrom.
func (i *Interest) ReadFrom(r tlv.Reader) error {
	return r.Read(i, 5)
}

var (
	castagnoliTable = crc32.MakeTable(crc32.Castagnoli)
)

// NewCRC32C creates a new CRC32C hash.
func NewCRC32C() hash.Hash {
	return crc32.New(castagnoliTable)
}

// WriteTo implements tlv.WriteTo.
//
// SHA256 digest will be populated if SignatureValue is empty.
func (d *Data) WriteTo(w tlv.Writer) (err error) {
	if len(d.SignatureValue) == 0 {
		var f func() hash.Hash
		switch d.SignatureInfo.SignatureType {
		case SignatureTypeDigestSHA256:
			f = sha256.New
		case SignatureTypeDigestCRC32C:
			f = NewCRC32C
		default:
			err = ErrNotSupported
			return
		}
		d.SignatureValue, err = tlv.Hash(f, d)
		if err != nil {
			return
		}
	}
	err = w.Write(d, 6)
	return
}

// ReadFrom implements tlv.ReadFrom.
//
// Signature will not be verified.
func (d *Data) ReadFrom(r tlv.Reader) error {
	return r.Read(d, 6)
}
