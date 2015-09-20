// Copyright 2015 Tai-Lin Chu. All rights reserved.
// Use of this source code is governed by GPL2 license.

// Package ndn implements named-data networking.
package ndn

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"hash/crc32"
	"strings"
	"time"

	"github.com/go-ndn/tlv"
)

type Interest struct {
	Name      Name      `tlv:"7"`
	Selectors Selectors `tlv:"9?"`
	Nonce     []byte    `tlv:"10"`
	LifeTime  uint64    `tlv:"12?"`
}

type Selectors struct {
	MinSuffixComponents       uint64     `tlv:"13?"`
	MaxSuffixComponents       uint64     `tlv:"14?"`
	PublisherPublicKeyLocator KeyLocator `tlv:"15?"`
	Exclude                   Exclude    `tlv:"16?"`
	ChildSelector             uint64     `tlv:"17?"`
	MustBeFresh               bool       `tlv:"18?"`
}

func (sel *Selectors) Match(name string, d *Data, t time.Time) bool {
	interestLen := strings.Count(name, "/")
	suffix := d.Name.Len() - interestLen
	if sel.MinSuffixComponents > uint64(suffix) {
		return false
	}
	if sel.MaxSuffixComponents != 0 && sel.MaxSuffixComponents < uint64(suffix) {
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
	if suffix > 0 && sel.Exclude.Match(d.Name.Components[interestLen]) {
		return false
	}
	if sel.MustBeFresh && !t.IsZero() && d.MetaInfo.FreshnessPeriod != 0 &&
		time.Since(t) > time.Duration(d.MetaInfo.FreshnessPeriod)*time.Millisecond {
		return false
	}
	return true
}

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
	FinalBlockID    FinalBlockID `tlv:"26?"`
	EncryptionType  uint64       `tlv:"30?"`
	CompressionType uint64       `tlv:"31?"`
}

type FinalBlockID struct {
	Component Component `tlv:"8"`
}

const (
	EncryptionTypeNone       uint64 = 0
	EncryptionTypeAESWithCTR        = 1
)

const (
	CompressionTypeNone uint64 = 0
	CompressionTypeGZIP        = 1
)

type SignatureInfo struct {
	SignatureType  uint64         `tlv:"27"`
	KeyLocator     KeyLocator     `tlv:"28?"`
	ValidityPeriod ValidityPeriod `tlv:"253?"`
}

const (
	SignatureTypeDigestSHA256    uint64 = 0
	SignatureTypeSHA256WithRSA          = 1
	SignatureTypeDigestCRC32C           = 2
	SignatureTypeSHA256WithECDSA        = 3
	SignatureTypeSHA256WithHMAC         = 4
)

type KeyLocator struct {
	Name   Name   `tlv:"7?"`
	Digest []byte `tlv:"29?"`
}

const (
	ISO8601 = "20060102T150405"
)

type ValidityPeriod struct {
	NotBefore string `tlv:"254"`
	NotAfter  string `tlv:"255"`
}

func newNonce() []byte {
	b := make([]byte, 4)
	rand.Read(b)
	return b
}

// WriteTo writes interest to tlv.Writer after it populates nonce
func (i *Interest) WriteTo(w tlv.Writer) error {
	if len(i.Nonce) == 0 {
		i.Nonce = newNonce()
	}
	return w.Write(i, 5)
}

func (i *Interest) ReadFrom(r tlv.Reader) error {
	return r.Read(i, 5)
}

var (
	castagnoliTable = crc32.MakeTable(crc32.Castagnoli)
)

func NewCRC32C() hash.Hash {
	return crc32.New(castagnoliTable)
}

// WriteTo writes data to tlv.Writer after it populates digest
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

// ReadFrom reads data from tlv.Reader but it does not verify the signature
func (d *Data) ReadFrom(r tlv.Reader) error {
	return r.Read(d, 6)
}
