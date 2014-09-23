// Copyright 2014 Tai-Lin Chu. All rights reserved.
// Use of this source code is governed by GPL2 license.

// Package ndn implements ndn(named-data networking) client library. It is intended to work with nfd.
//
// Examples
//
// see https://github.com/taylorchu/ndn/blob/master/face_test.go
//
package ndn

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/taylorchu/tlv"
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
	return tlv.Unmarshal(bufio.NewReader(bytes.NewBuffer(b)), i, valType)
}

type ReadFrom interface {
	ReadFrom(tlv.PeekReader) error
}

type WriteTo interface {
	WriteTo(tlv.Writer) error
}

func Copy(from WriteTo, to ReadFrom) (err error) {
	buf := new(bytes.Buffer)
	err = from.WriteTo(buf)
	if err != nil {
		return
	}
	err = to.ReadFrom(bufio.NewReader(buf))
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
	Exclude                   []byte     `tlv:"16?"`
	ChildSelector             uint64     `tlv:"17?"`
	MustBeFresh               bool       `tlv:"18?"`
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
	FinalBlockId    FinalBlockId `tlv:"26?"`
}

type FinalBlockId struct {
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

// WriteTo writes interest to tlv.Writer after it populates nonce and lifeTime(if not defined) automatically
func (this *Interest) WriteTo(w tlv.Writer) error {
	this.Nonce = newNonce()
	if this.LifeTime == 0 {
		this.LifeTime = 4000
	}
	return tlv.Marshal(w, this, 5)
}

func (this *Interest) ReadFrom(r tlv.PeekReader) error {
	return tlv.Unmarshal(r, this, 5)
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

// WriteTo writes data to tlv.Writer after it signs data automatically
//
// If SignKey is not ready, it will only provide DigestSha256.
func (this *Data) WriteTo(w tlv.Writer) (err error) {
	digest, err := newSha256(this)
	if err != nil {
		return
	}
	sigType := SignKey.SignatureType()
	switch sigType {
	case SignatureTypeDigestSha256:
		this.SignatureValue = digest
	default:
		this.SignatureInfo.SignatureType = sigType
		this.SignatureInfo.KeyLocator.Name = SignKey.Name.CertificateName()
		this.SignatureValue, err = SignKey.sign(digest)
		if err != nil {
			return
		}
	}
	err = tlv.Marshal(w, this, 6)
	return
}

// ReadFrom reads data from tlv.PeekReader but it does not verify the signature
//
// If DigestSha256 is present, the integrity will be verified.
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
	case SignatureTypeDigestSha256:
		if !bytes.Equal(this.SignatureValue, digest) {
			err = fmt.Errorf("cannot verify sha256")
			return
		}
	}
	return
}
