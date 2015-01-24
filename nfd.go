package ndn

import (
	"time"

	"github.com/go-ndn/tlv"
)

// see http://redmine.named-data.net/projects/nfd/wiki/Management
type Command struct {
	Localhost      string                  `tlv:"8"`
	Nfd            string                  `tlv:"8"`
	Module         string                  `tlv:"8"`
	Command        string                  `tlv:"8"`
	Parameters     parametersComponent     `tlv:"8"`
	Timestamp      uint64                  `tlv:"8"`
	Nonce          []byte                  `tlv:"8"`
	SignatureInfo  signatureInfoComponent  `tlv:"8"`
	SignatureValue signatureValueComponent `tlv:"8*"`
}

func (this *Command) WriteTo(w tlv.Writer) (err error) {
	if len(this.SignatureValue.SignatureValue) == 0 {
		this.Localhost = "localhost"
		this.Nfd = "nfd"
		this.Timestamp = uint64(time.Now().UTC().UnixNano() / 1000000)
		this.Nonce = newNonce()
		this.SignatureInfo.SignatureInfo.SignatureType = SignKey.SignatureType()
		this.SignatureInfo.SignatureInfo.KeyLocator.Name = SignKey.Name

		this.SignatureValue.SignatureValue, err = SignKey.sign(this)
		if err != nil {
			return
		}
	}
	err = tlv.Marshal(w, this, 7)
	return
}

func (this *Command) ReadFrom(r tlv.PeekReader) error {
	return tlv.Unmarshal(r, this, 7)
}

type parametersComponent struct {
	Parameters Parameters `tlv:"104"`
}

type signatureInfoComponent struct {
	SignatureInfo SignatureInfo `tlv:"22"`
}

type signatureValueComponent struct {
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
	LSA                 *LSA     `tlv:"112?"` // TODO: remove
}

type Strategy struct {
	Name Name `tlv:"7"`
}

type StrategyChoice struct {
	Name     Name     `tlv:"7"`
	Strategy Strategy `tlv:"107"`
}

type ControlResponse struct {
	StatusCode uint64     `tlv:"102"`
	StatusText string     `tlv:"103"`
	Parameters Parameters `tlv:"104?"`
}

type NextHopRecord struct {
	FaceId uint64 `tlv:"105"`
	Cost   uint64 `tlv:"106"`
}

type FibEntry struct {
	Name    Name            `tlv:"7"`
	NextHop []NextHopRecord `tlv:"129?"`
}

type FaceEntry struct {
	FaceId           uint64 `tlv:"105"`
	Uri              string `tlv:"114"`
	LocalUri         string `tlv:"129"`
	ExpirationPeriod uint64 `tlv:"109?"`
	Scope            uint64 `tlv:"132"`
	Persistency      uint64 `tlv:"133"`
	LinkType         uint64 `tlv:"134"`
	InInterest       uint64 `tlv:"144"`
	InData           uint64 `tlv:"145"`
	OutInterest      uint64 `tlv:"146"`
	OutData          uint64 `tlv:"147"`
	InByte           uint64 `tlv:"148"`
	OutByte          uint64 `tlv:"149"`
}

type RibEntry struct {
	Name  Name    `tlv:"7"`
	Route []Route `tlv:"129?"`
}

type Route struct {
	FaceId           uint64 `tlv:"105"`
	Origin           uint64 `tlv:"111"`
	Cost             uint64 `tlv:"106"`
	Flags            uint64 `tlv:"108"`
	ExpirationPeriod uint64 `tlv:"109?"`
}

type ForwarderStatus struct {
	NfdVersion       string `tlv:"128"`
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

// TODO: remove
type LSA struct {
	Version  uint64     `tlv:"128"`
	Id       string     `tlv:"105"`
	Name     []string   `tlv:"7?"`
	Neighbor []Neighbor `tlv:"129?"`
}

// TODO: remove
type Neighbor struct {
	Id   string `tlv:"105"`
	Cost uint64 `tlv:"106"`
}
