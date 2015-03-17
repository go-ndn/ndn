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

func (cmd *Command) WriteTo(w tlv.Writer) (err error) {
	if len(cmd.SignatureValue.SignatureValue) == 0 {
		cmd.Localhost = "localhost"
		cmd.Nfd = "nfd"
		cmd.Timestamp = uint64(time.Now().UTC().UnixNano() / 1000000)
		cmd.Nonce = newNonce()
		cmd.SignatureInfo.SignatureInfo.SignatureType = SignKey.SignatureType()
		cmd.SignatureInfo.SignatureInfo.KeyLocator.Name = SignKey.Name

		cmd.SignatureValue.SignatureValue, err = SignKey.sign(cmd)
		if err != nil {
			return
		}
	}
	err = tlv.Marshal(w, cmd, 7)
	return
}

func (cmd *Command) ReadFrom(r tlv.Reader) error {
	return tlv.Unmarshal(r, cmd, 7)
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
	FaceID              uint64   `tlv:"105?"`
	URI                 string   `tlv:"114?"`
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

// forwarder dataset
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

// face dataset
type FaceEntry struct {
	FaceID           uint64 `tlv:"105"`
	URI              string `tlv:"114"`
	LocalURI         string `tlv:"129"`
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

// fib dataset
type FibEntry struct {
	Name    Name            `tlv:"7"`
	NextHop []NextHopRecord `tlv:"129"`
}

type NextHopRecord struct {
	FaceID uint64 `tlv:"105"`
	Cost   uint64 `tlv:"106"`
}

// rib dataset
type RibEntry struct {
	Name  Name    `tlv:"7"`
	Route []Route `tlv:"129"`
}

type Route struct {
	FaceID           uint64 `tlv:"105"`
	Origin           uint64 `tlv:"111"`
	Cost             uint64 `tlv:"106"`
	Flags            uint64 `tlv:"108"`
	ExpirationPeriod uint64 `tlv:"109?"`
}

// strategy choice dataset
type StrategyChoice struct {
	Name     Name     `tlv:"7"`
	Strategy Strategy `tlv:"107"`
}
