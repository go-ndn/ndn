package ndn

import (
	"errors"
	"math/rand"
	"time"

	"github.com/go-ndn/tlv"
)

// Errors introduced by communicating with forwarder.
var (
	ErrTimeout        = errors.New("timeout")
	ErrResponseStatus = errors.New("bad command response status")
)

// Command alters forwarder state.
//
// See http://redmine.named-data.net/projects/nfd/wiki/Management.
type Command struct {
	Local          string                  `tlv:"8"`
	NFD            string                  `tlv:"8"`
	Module         string                  `tlv:"8"`
	Command        string                  `tlv:"8"`
	Parameters     parametersComponent     `tlv:"8"`
	Timestamp      uint64                  `tlv:"8"`
	Nonce          uint64                  `tlv:"8"`
	SignatureInfo  signatureInfoComponent  `tlv:"8"`
	SignatureValue signatureValueComponent `tlv:"8*"`
}

// WriteTo implements tlv.WriteTo.
func (cmd *Command) WriteTo(w tlv.Writer) error {
	return w.Write(cmd, 7)
}

// ReadFrom implements tlv.ReadFrom.
func (cmd *Command) ReadFrom(r tlv.Reader) error {
	return r.Read(cmd, 7)
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

// Parameters contains arguments to command.
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
	FacePersistency     uint64   `tlv:"133?"`
}

// Strategy is a forwarding strategy for a namespace.
type Strategy struct {
	Name Name `tlv:"7"`
}

// CommandResponse contains status code and text.
//
// StatusCode generally follows HTTP convention [RFC2616].
type CommandResponse struct {
	StatusCode uint64     `tlv:"102"`
	StatusText string     `tlv:"103"`
	Parameters Parameters `tlv:"104?"`
}

// ForwarderStatus is not available in go-nfd.
type ForwarderStatus struct {
	NFDVersion       string `tlv:"128"`
	StartTimestamp   uint64 `tlv:"129"`
	CurrentTimestamp uint64 `tlv:"130"`
	NameTreeEntry    uint64 `tlv:"131"`
	FIBEntry         uint64 `tlv:"132"`
	PITEntry         uint64 `tlv:"133"`
	MeasurementEntry uint64 `tlv:"134"`
	CSEntry          uint64 `tlv:"135"`
	InInterest       uint64 `tlv:"144"`
	InData           uint64 `tlv:"145"`
	InNack           uint64 `tlv:"151"`
	OutInterest      uint64 `tlv:"146"`
	OutData          uint64 `tlv:"147"`
	OutNack          uint64 `tlv:"152"`
}

// FaceStatus is not available in go-nfd.
type FaceStatus struct {
	FaceID           uint64 `tlv:"105"`
	URI              string `tlv:"114"`
	LocalURI         string `tlv:"129"`
	ExpirationPeriod uint64 `tlv:"109?"`
	Scope            uint64 `tlv:"132"`
	Persistency      uint64 `tlv:"133"`
	LinkType         uint64 `tlv:"134"`
	InInterest       uint64 `tlv:"144"`
	InData           uint64 `tlv:"145"`
	InNack           uint64 `tlv:"151"`
	OutInterest      uint64 `tlv:"146"`
	OutData          uint64 `tlv:"147"`
	OutNack          uint64 `tlv:"152"`
	InByte           uint64 `tlv:"148"`
	OutByte          uint64 `tlv:"149"`
}

// FIBEntry is not available in go-nfd.
type FIBEntry struct {
	Name    Name            `tlv:"7"`
	NextHop []NextHopRecord `tlv:"129"`
}

// NextHopRecord is not available in go-nfd.
type NextHopRecord struct {
	FaceID uint64 `tlv:"105"`
	Cost   uint64 `tlv:"106"`
}

// RIBEntry specifies all routes under a name.
type RIBEntry struct {
	Name  Name    `tlv:"7"`
	Route []Route `tlv:"129"`
}

// Route contains information about a route.
type Route struct {
	FaceID           uint64 `tlv:"105"`
	Origin           uint64 `tlv:"111"`
	Cost             uint64 `tlv:"106"`
	Flags            uint64 `tlv:"108"`
	ExpirationPeriod uint64 `tlv:"109?"`
}

// StrategyChoice is not available in go-nfd.
type StrategyChoice struct {
	Name     Name     `tlv:"7"`
	Strategy Strategy `tlv:"107"`
}

// SendControl sends command and waits for its response.
//
// ErrResponseStatus is returned if the status code is not 200.
func SendControl(w Sender, module, command string, params *Parameters, key Key) (err error) {
	cmd := &Command{
		Local:     "localhost",
		NFD:       "nfd",
		Module:    module,
		Command:   command,
		Timestamp: uint64(time.Now().UnixNano() / 1000000),
		Nonce:     uint64(rand.Uint32()),
	}
	cmd.Parameters.Parameters = *params
	cmd.SignatureInfo.SignatureInfo.SignatureType = key.SignatureType()
	cmd.SignatureInfo.SignatureInfo.KeyLocator.Name = key.Locator()
	cmd.SignatureValue.SignatureValue, err = key.Sign(cmd)
	if err != nil {
		return
	}

	i := new(Interest)
	err = tlv.Copy(&i.Name, cmd)
	if err != nil {
		return
	}
	d, ok := <-w.SendInterest(i)
	if !ok {
		err = ErrTimeout
		return
	}
	var resp CommandResponse
	err = tlv.Unmarshal(d.Content, &resp, 101)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = ErrResponseStatus
		return
	}
	return
}
