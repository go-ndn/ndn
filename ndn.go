// Copyright 2014 Tai-Lin Chu. All rights reserved.
// Use of this source code is governed by GPL2 license.

// Package ndn implements ndn(named-data networking) client library. It is intended to work with nfd.
//
// Examples
//
// see https://github.com/go-ndn/ndn/blob/master/face_test.go
//
package ndn

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-ndn/tlv"
)

// Print dumps interest, data, or any variable in detail for debugging
func Print(i ...interface{}) {
	spew.Dump(i...)
}

func Marshal(i interface{}, valType uint64) (b []byte, err error) {
	buf := new(bytes.Buffer)
	err = tlv.Marshal(buf, i, valType)
	if err != nil {
		return
	}
	b = buf.Bytes()
	return
}

func Unmarshal(b []byte, i interface{}, valType uint64) error {
	return tlv.Unmarshal(tlv.NewReader(bytes.NewReader(b)), i, valType)
}

func Copy(from tlv.WriteTo, to tlv.ReadFrom) (err error) {
	buf := new(bytes.Buffer)
	err = from.WriteTo(buf)
	if err != nil {
		return
	}
	err = to.ReadFrom(tlv.NewReader(buf))
	return
}

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
	suffix := len(d.Name.Components) - strings.Count(name, "/") + 1
	if sel.MinSuffixComponents != 0 && sel.MinSuffixComponents > uint64(suffix) {
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
	if sel.MustBeFresh && !t.IsZero() && time.Now().Sub(t) > time.Duration(d.MetaInfo.FreshnessPeriod)*time.Millisecond {
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
	SignatureTypeDigestSha256    uint64 = 0
	SignatureTypeSha256WithRsa          = 1
	SignatureTypeSha256WithEcdsa        = 3 // 2 is already used
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

// WriteTo writes interest to tlv.Writer after it populates nonce
func (i *Interest) WriteTo(w tlv.Writer) error {
	if len(i.Nonce) == 0 {
		i.Nonce = newNonce()
	}
	return tlv.Marshal(w, i, 5)
}

func (i *Interest) ReadFrom(r tlv.Reader) error {
	return tlv.Unmarshal(r, i, 5)
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

// WriteTo writes data to tlv.Writer after it populates sha256 digest
func (d *Data) WriteTo(w tlv.Writer) (err error) {
	if len(d.SignatureValue) == 0 {
		d.SignatureInfo.SignatureType = SignatureTypeDigestSha256
		d.SignatureValue, err = newSha256(d)
		if err != nil {
			return
		}
	}
	err = tlv.Marshal(w, d, 6)
	return
}

// ReadFrom reads data from tlv.Reader but it does not verify the signature
func (d *Data) ReadFrom(r tlv.Reader) error {
	return tlv.Unmarshal(r, d, 6)
}
