// Copyright 2014 Tai-Lin Chu. All rights reserved.
// Use of this source code is governed by GPL2 license.

// Package ndn implements ndn(named-data networking) client library.
package ndn

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/go-ndn/tlv"
)

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
	Exclude                   Exclude    `tlv:"16?"`
	ChildSelector             uint64     `tlv:"17?"`
	MustBeFresh               bool       `tlv:"18?"`
}

func (sel *Selectors) Match(name string, d *Data, t time.Time) bool {
	suffix := len(d.Name.Components) - strings.Count(name, "/")
	if sel.MinSuffixComponents > uint64(suffix) {
		return false
	}
	if sel.MaxSuffixComponents != 0 && sel.MaxSuffixComponents < uint64(suffix) {
		return false
	}
	if len(sel.PublisherPublicKeyLocator.Name.Components) != 0 &&
		sel.PublisherPublicKeyLocator.Name.Compare(d.SignatureInfo.KeyLocator.Name) != 0 {
		return false
	}
	if len(sel.PublisherPublicKeyLocator.Digest) != 0 &&
		!bytes.Equal(sel.PublisherPublicKeyLocator.Digest, d.SignatureInfo.KeyLocator.Digest) {
		return false
	}
	if suffix > 0 && sel.Exclude.Match(d.Name.Components[len(d.Name.Components)-suffix]) {
		return false
	}
	if sel.MustBeFresh && !t.IsZero() && time.Since(t) > time.Duration(d.MetaInfo.FreshnessPeriod)*time.Millisecond {
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
}

type FinalBlockID struct {
	Component Component `tlv:"8"`
}

type SignatureInfo struct {
	SignatureType uint64     `tlv:"27"`
	KeyLocator    KeyLocator `tlv:"28?"`
}

const (
	SignatureTypeDigestSHA256    uint64 = 0
	SignatureTypeSHA256WithRSA          = 1
	SignatureTypeSHA256WithECDSA        = 3 // 2 is already used
)

type KeyLocator struct {
	Name   Name   `tlv:"7?"`
	Digest []byte `tlv:"29?"`
}

func newNonce() []byte {
	b := make([]byte, 4)
	rand.Read(b)
	return b
}

func NewSHA256(v interface{}) (digest []byte, err error) {
	h := sha256.New()
	err = tlv.Data(h, v)
	if err != nil {
		return
	}
	digest = h.Sum(nil)
	return
}

func writePacket(w tlv.Writer, v interface{}, valType uint64) (err error) {
	b, err := tlv.MarshalByte(v, valType)
	if err != nil {
		return
	}
	_, err = w.Write(b)
	return
}

// WriteTo writes interest to tlv.Writer after it populates nonce
func (i *Interest) WriteTo(w tlv.Writer) error {
	if len(i.Nonce) == 0 {
		i.Nonce = newNonce()
	}
	return writePacket(w, i, 5)
}

func (i *Interest) ReadFrom(r tlv.Reader) error {
	return tlv.Unmarshal(r, i, 5)
}

// WriteTo writes data to tlv.Writer after it populates sha256 digest
func (d *Data) WriteTo(w tlv.Writer) (err error) {
	if len(d.SignatureValue) == 0 {
		d.SignatureInfo.SignatureType = SignatureTypeDigestSHA256
		d.SignatureValue, err = NewSHA256(d)
		if err != nil {
			return
		}
	}
	err = writePacket(w, d, 6)
	return
}

// ReadFrom reads data from tlv.Reader but it does not verify the signature
func (d *Data) ReadFrom(r tlv.Reader) error {
	return tlv.Unmarshal(r, d, 6)
}
