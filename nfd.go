package ndn

import (
	"bytes"
	"fmt"
	"github.com/taylorchu/tlv"
	"time"
)

type ControlPacket struct {
	Name      SignedName `tlv:"7"`
	Selectors Selectors  `tlv:"9?"`
	Nonce     []byte     `tlv:"10"`
	Scope     uint64     `tlv:"11?"`
	LifeTime  uint64     `tlv:"12?"`
}

type SignedName struct {
	Localhost      string                  `tlv:"8"`
	Nfd            string                  `tlv:"8"`
	Module         string                  `tlv:"8"`
	Command        string                  `tlv:"8"`
	Parameters     ParametersComponent     `tlv:"8"`
	Timestamp      uint64                  `tlv:"8"`
	Nonce          []byte                  `tlv:"8"`
	SignatureInfo  SignatureInfoComponent  `tlv:"8"`
	SignatureValue SignatureValueComponent `tlv:"8*"`
}

func (this *ControlPacket) WriteTo(w tlv.Writer) (err error) {
	this.Name.Localhost = "localhost"
	this.Name.Nfd = "nfd"
	this.Name.Timestamp = uint64(time.Now().UnixNano() / 1000000)
	this.Name.Nonce = newNonce()
	this.Name.SignatureInfo.SignatureInfo.SignatureType = SignKey.SignatureType()
	this.Name.SignatureInfo.SignatureInfo.KeyLocator.Name = SignKey.LocatorName()

	digest, err := newSha256(this.Name)
	if err != nil {
		return
	}
	this.Name.SignatureValue.SignatureValue, err = SignKey.Sign(digest)
	if err != nil {
		return
	}
	this.Nonce = newNonce()
	err = tlv.Marshal(w, this, 5)
	return
}

type ParametersComponent struct {
	Parameters Parameters `tlv:"104"`
}

type SignatureInfoComponent struct {
	SignatureInfo SignatureInfo `tlv:"22"`
}

type SignatureValueComponent struct {
	SignatureValue []byte `tlv:"23"`
}

type Parameters struct {
	Name                Name     `tlv:"7?"`
	FaceId              uint64   `tlv:"105?"`
	Uri                 string   `tlv:"114?"`
	LocalControlFeature uint64   `tlv:"110?"`
	Origin              uint64   `tlv:"111?"`
	Cost                uint64   `tlv:"106?"`
	Flags               uint64   `tlv:"108?"`
	Strategy            Strategy `tlv:"107?"`
	ExpirationPeriod    uint64   `tlv:"109?"`
}

type Strategy struct {
	Name Name `tlv:"7"`
}

type ControlResponse struct {
	StatusCode uint64     `tlv:"102"`
	StatusText string     `tlv:"103"`
	Parameters Parameters `tlv:"104?"`
}

type Response struct {
	Response ControlResponse `tlv:"101"`
}

type ControlResponsePacket struct {
	Name           SignedName    `tlv:"7"`
	MetaInfo       MetaInfo      `tlv:"20"`
	Content        Response      `tlv:"21"`
	SignatureInfo  SignatureInfo `tlv:"22"`
	SignatureValue []byte        `tlv:"23*"`
}

func (this *ControlResponsePacket) ReadFrom(r tlv.PeekReader) error {
	err := tlv.Unmarshal(r, this, 6)
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
			return fmt.Errorf("cannot verify sha256")
		}
	case SignatureTypeSha256WithRsa:
		// TODO: enable rsa
	}
	return nil
}

type NextHopRecord struct {
	FaceId uint64 `tlv:"105"`
	Cost   uint64 `tlv:"106"`
}

type FibEntry struct {
	Name     Name            `tlv:"7"`
	NextHops []NextHopRecord `tlv:"129"`
}

type FibEntries struct {
	FibEntries []FibEntry `tlv:"128"`
}

type FibEntryPacket struct {
	Name           Name          `tlv:"7"`
	MetaInfo       MetaInfo      `tlv:"20"`
	Content        FibEntries    `tlv:"21"`
	SignatureInfo  SignatureInfo `tlv:"22"`
	SignatureValue []byte        `tlv:"23*"`
}

func (this *FibEntryPacket) ReadFrom(r tlv.PeekReader) error {
	err := tlv.Unmarshal(r, this, 6)
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
			return fmt.Errorf("cannot verify sha256")
		}
	case SignatureTypeSha256WithRsa:
		// TODO: enable rsa
	}
	return nil
}

type FaceEntry struct {
	FaceId      uint64 `tlv:"105"`
	Uri         string `tlv:"114"`
	LocalUri    string `tlv:"129"`
	FaceFlag    uint64 `tlv:"194"`
	InInterest  uint64 `tlv:"144"`
	InData      uint64 `tlv:"145"`
	OutInterest uint64 `tlv:"146"`
	OutData     uint64 `tlv:"147"`
}

type FaceEntries struct {
	FaceEntries []FaceEntry `tlv:"128"`
}

type FaceEntryPacket struct {
	Name           Name          `tlv:"7"`
	MetaInfo       MetaInfo      `tlv:"20"`
	Content        FaceEntries   `tlv:"21"`
	SignatureInfo  SignatureInfo `tlv:"22"`
	SignatureValue []byte        `tlv:"23*"`
}

func (this *FaceEntryPacket) ReadFrom(r tlv.PeekReader) error {
	err := tlv.Unmarshal(r, this, 6)
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
			return fmt.Errorf("cannot verify sha256")
		}
	case SignatureTypeSha256WithRsa:
		// TODO: enable rsa
	}
	return nil
}

type ForwarderStatus struct {
	NfdVersion       uint64 `tlv:"128"`
	StartTimestamp   uint64 `tlv:"129"`
	CurrentTimestamp uint64 `tlv:"130"`
	NameTreeEntry    uint64 `tlv:"131"`
	FibEntry         uint64 `tlv:"132"`
	PitEntry         uint64 `tlv:"133"`
	MeasurementEntry uint64 `tlv:"134"`
	CsEntry          uint64 `tlv:"135"`
	InInterest       uint64 `tlv:"144"`
	InData           uint64 `tlv:"145"`
	OutInterest      uint64 `tlv:"146"`
	OutData          uint64 `tlv:"147"`
}

type ForwarderStatusPacket struct {
	Name           Name            `tlv:"7"`
	MetaInfo       MetaInfo        `tlv:"20"`
	Content        ForwarderStatus `tlv:"21"`
	SignatureInfo  SignatureInfo   `tlv:"22"`
	SignatureValue []byte          `tlv:"23*"`
}

func (this *ForwarderStatusPacket) ReadFrom(r tlv.PeekReader) error {
	err := tlv.Unmarshal(r, this, 6)
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
			return fmt.Errorf("cannot verify sha256")
		}
	case SignatureTypeSha256WithRsa:
		// TODO: enable rsa
	}
	return nil
}
