package ndn

import (
	"github.com/davecgh/go-spew/spew"
	"time"
)

/*
   interact with NFD
*/

const (
	CONTROL_PARAMETERS    uint64 = 104
	FACE_ID                      = 105
	URI                          = 114
	LOCAL_CONTROL_FEATURE        = 110
	COST                         = 106
	STRATEGY                     = 107
	CONTROL_RESPONSE             = 101
	STATUS_CODE                  = 102
	STATUS_TEXT                  = 103
	// status dataset
	FIB_ENTRY           = 128
	NEXT_HOP_RECORD     = 129
	NFD_VERSION         = 128
	START_TIMESTAMP     = 129
	CURRENT_TIMESTAMP   = 130
	N_NAME_TREE_ENTRIES = 131
	N_FIB_ENTRY         = 132
	N_PIT_ENTRY         = 133
	N_MEASUREMENT_ENTRY = 134
	N_CS_ENTRY          = 135
	N_IN_INTEREST       = 144
	N_IN_DATA           = 145
	N_OUT_INTEREST      = 146
	N_OUT_DATA          = 147
	FACE_ENTRY          = 128
	LOCAL_URI           = 129
	FACE_FLAG           = 194
)

var (
	controlResponseFormat = node{Type: CONTROL_RESPONSE, Children: []node{
		{Type: STATUS_CODE},
		{Type: STATUS_TEXT},
		{Type: CONTROL_PARAMETERS, Count: ZERO_OR_ONE, Children: controlParametersContentFormat},
		forwarderStatusFormat,
		fibStatusFormat,
		faceStatusFormat,
	}}
	controlParametersContentFormat = []node{
		{Type: NAME, Count: ZERO_OR_ONE, Children: []node{{Type: NAME_COMPONENT, Count: ZERO_OR_MORE}}},
		{Type: FACE_ID, Count: ZERO_OR_ONE},
		{Type: URI, Count: ZERO_OR_ONE},
		{Type: LOCAL_CONTROL_FEATURE, Count: ZERO_OR_ONE},
		{Type: COST, Count: ZERO_OR_ONE},
		{Type: STRATEGY, Count: ZERO_OR_ONE, Children: []node{
			nameFormat,
		}},
	}
	controlFormat = node{Type: NAME, Children: []node{
		{Type: NAME_COMPONENT}, // localhost
		{Type: NAME_COMPONENT}, // nfd
		{Type: NAME_COMPONENT}, // module
		{Type: NAME_COMPONENT}, // command
		{Type: NAME_COMPONENT, Children: []node{
			{Type: CONTROL_PARAMETERS, Children: controlParametersContentFormat}, // param
		}},
		{Type: NAME_COMPONENT}, // timestamp
		{Type: NAME_COMPONENT}, // random value
		{Type: NAME_COMPONENT, Children: []node{signatureInfoFormat}},
		{Type: NAME_COMPONENT, Children: []node{
			{Type: SIGNATURE_VALUE},
		}},
	}}
	forwarderStatusFormat = node{Type: GROUP_AND, Count: ZERO_OR_ONE, Children: []node{
		{Type: NFD_VERSION},
		{Type: START_TIMESTAMP},
		{Type: CURRENT_TIMESTAMP},
		{Type: N_NAME_TREE_ENTRIES},
		{Type: N_FIB_ENTRY},
		{Type: N_PIT_ENTRY},
		{Type: N_MEASUREMENT_ENTRY},
		{Type: N_CS_ENTRY},
		{Type: N_IN_INTEREST},
		{Type: N_IN_DATA},
		{Type: N_OUT_INTEREST},
		{Type: N_OUT_DATA},
	}}
	fibStatusFormat = node{Type: FIB_ENTRY, Count: ZERO_OR_MORE, Children: []node{
		nameFormat,
		{Type: NEXT_HOP_RECORD, Count: ONE_OR_MORE, Children: []node{
			{Type: FACE_ID},
			{Type: COST},
		}},
	}}
	faceStatusFormat = node{Type: FACE_ENTRY, Count: ZERO_OR_MORE, Children: []node{
		{Type: FACE_ID},
		{Type: LOCAL_URI},
		{Type: FACE_FLAG},
		{Type: N_IN_INTEREST},
		{Type: N_IN_DATA},
		{Type: N_OUT_INTEREST},
		{Type: N_OUT_DATA},
	}}
)

type Control struct {
	Module     string
	Command    string
	Parameters Parameters
}

type Parameters struct {
	Name                [][]byte
	FaceId              uint64
	Uri                 string
	LocalControlFeature uint64
	Cost                uint64
	Strategy            [][]byte
}

func (this *Parameters) encode() (parameters TLV, err error) {
	parameters = NewTLV(CONTROL_PARAMETERS)
	// name
	if len(this.Name) != 0 {
		parameters.Add(nameEncode(this.Name))
	}
	// face id
	if this.FaceId != 0 {
		faceId := NewTLV(FACE_ID)
		faceId.Value, err = encodeNonNeg(this.FaceId)
		if err != nil {
			return
		}
		parameters.Add(faceId)
	}
	// uri
	if len(this.Uri) != 0 {
		uri := NewTLV(URI)
		uri.Value = []byte(this.Uri)
		parameters.Add(uri)
	}
	// local control feature
	if this.LocalControlFeature != 0 {
		localControlFeature := NewTLV(LOCAL_CONTROL_FEATURE)
		localControlFeature.Value, err = encodeNonNeg(this.LocalControlFeature)
		if err != nil {
			return
		}
		parameters.Add(localControlFeature)
	}
	// cost
	if this.Cost != 0 {
		cost := NewTLV(COST)
		cost.Value, err = encodeNonNeg(this.Cost)
		if err != nil {
			return
		}
		parameters.Add(cost)
	}
	// strategy
	if len(this.Strategy) != 0 {
		strategy := NewTLV(STRATEGY)
		strategy.Add(nameEncode(this.Strategy))
		parameters.Add(strategy)
	}
	return
}

func (this *Parameters) decode(parameters TLV) (err error) {
	for _, c := range parameters.Children {
		switch c.Type {
		case NAME:
			this.Name = nameDecode(c)
		case FACE_ID:
			this.FaceId, err = decodeNonNeg(c.Value)
			if err != nil {
				return
			}
		case URI:
			this.Uri = string(c.Value)
		case LOCAL_CONTROL_FEATURE:
			this.LocalControlFeature, err = decodeNonNeg(c.Value)
			if err != nil {
				return
			}
		case COST:
			this.Cost, err = decodeNonNeg(c.Value)
			if err != nil {
				return
			}
		case STRATEGY:
			this.Strategy = nameDecode(c.Children[0])
		}
	}
	return
}

func (this *Control) Print() {
	spew.Dump(*this)
}

func (this *Control) Encode() (i *Interest, err error) {
	name := nameFromString("/localhost/nfd/" + this.Module)
	if len(this.Command) > 0 {
		name = append(name, []byte(this.Command))
	}
	parameters, err := this.Parameters.encode()
	if err != nil {
		return
	}
	b, err := parameters.Encode()
	if err != nil {
		return
	}
	name = append(name, b)
	// signed

	// timestamp
	b, err = encodeNonNeg(uint64(time.Now().UnixNano() / 1000000))
	if err != nil {
		return
	}
	name = append(name, b)
	// random value
	name = append(name, newNonce())

	// signature info
	signatureInfo := NewTLV(SIGNATURE_INFO)
	// signature type
	signatureType := NewTLV(SIGNATURE_TYPE)
	signatureType.Value, err = encodeNonNeg(SIGNATURE_TYPE_SIGNATURE_SHA_256_WITH_RSA)
	if err != nil {
		return
	}
	signatureInfo.Add(signatureType)
	// add empty keyLocator for rsa
	keyLocator := NewTLV(KEY_LOCATOR)
	keyLocator.Add(nameEncode(nameFromString("/testing/KEY/pubkey/ID-CERT")))
	signatureInfo.Add(keyLocator)

	b, err = signatureInfo.Encode()
	if err != nil {
		return
	}
	name = append(name, b)

	// signature value
	signatureValue := NewTLV(SIGNATURE_VALUE)
	signatureValue.Value, err = signRSA(nameEncode(name).Children)
	if err != nil {
		return
	}
	b, err = signatureValue.Encode()
	if err != nil {
		return
	}
	name = append(name, b)

	// final encode
	i = NewInterest("")
	i.Name = name
	i.Selectors.MustBeFresh = true
	i.Selectors.ChildSelector = CHILD_SELECTOR_LAST
	return
}

func (this *Control) Decode(i *Interest) (err error) {
	name := nameEncode(i.Name)
	b, err := name.Encode()
	if err != nil {
		return
	}
	ctrl, err := match(controlFormat, b)
	if err != nil {
		return
	}
	// module
	this.Module = string(ctrl.Children[2].Value)
	// command
	this.Command = string(ctrl.Children[3].Value)
	// parameters
	err = this.Parameters.decode(ctrl.Children[4].Children[0])
	if err != nil {
		return
	}

	// TODO: enable rsa
	// signatureValue := ctrl.Children[8].Children[0].Value
	// if !verifyRSA(ctrl.Children[:8], signatureValue) {
	// 	err = errors.New("cannot verify rsa")
	// 	return
	// }
	return
}

type ControlResponse struct {
	StatusCode      uint64
	StatusText      string
	Parameters      Parameters
	ForwarderStatus map[uint64]uint64
	FibStatus       []FibEntry
	FaceStatus      []FaceEntry
}

type NextHopRecord struct {
	FaceId uint64
	Cost   uint64
}

type FibEntry struct {
	Name     [][]byte
	NextHops []NextHopRecord
}

type FaceEntry map[uint64]interface{}

const (
	STATUS_CODE_OK             uint64 = 200
	STATUS_CODE_ARGS_INCORRECT        = 400
	STATUS_CODE_NOT_AUTHORIZED        = 403
	STATUS_CODE_NOT_FOUND             = 404
	STATUS_CODE_NOT_SUPPORTED         = 501
)

func (this *ControlResponse) Print() {
	spew.Dump(*this)
}

func (this *ControlResponse) Encode() (d *Data, err error) {
	controlResponse := NewTLV(CONTROL_RESPONSE)
	// status code
	statusCode := NewTLV(STATUS_CODE)
	statusCode.Value, err = encodeNonNeg(this.StatusCode)
	if err != nil {
		return
	}
	controlResponse.Add(statusCode)
	// status text
	statusText := NewTLV(STATUS_TEXT)
	statusText.Value = []byte(this.StatusText)
	controlResponse.Add(statusText)

	// parameters
	parameters, err := this.Parameters.encode()
	if err != nil {
		return
	}
	if len(parameters.Children) != 0 {
		controlResponse.Add(parameters)
	}
	// fib status
	for _, c := range this.FibStatus {
		fibEntry := NewTLV(FIB_ENTRY)
		fibEntry.Add(nameEncode(c.Name))
		for _, cc := range c.NextHops {
			nextHop := NewTLV(NEXT_HOP_RECORD)
			// face id
			faceId := NewTLV(FACE_ID)
			faceId.Value, err = encodeNonNeg(cc.FaceId)
			if err != nil {
				return
			}
			nextHop.Add(faceId)
			// cost
			cost := NewTLV(COST)
			cost.Value, err = encodeNonNeg(cc.Cost)
			if err != nil {
				return
			}
			nextHop.Add(cost)
			fibEntry.Add(nextHop)
		}
		controlResponse.Add(fibEntry)
	}
	// forwarder status
	if len(this.ForwarderStatus) > 0 {
		for _, c := range forwarderStatusFormat.Children {
			tlv := NewTLV(c.Type)
			tlv.Value, err = encodeNonNeg(this.ForwarderStatus[c.Type])
			if err != nil {
				return
			}
			controlResponse.Add(tlv)
		}
	}
	// face status
	for _, c := range this.FaceStatus {
		face := NewTLV(FACE_ENTRY)
		for _, cc := range faceStatusFormat.Children {
			tlv := NewTLV(cc.Type)
			switch cc.Type {
			case LOCAL_URI:
				tlv.Value = []byte(c[cc.Type].(string))
			default:
				tlv.Value, err = encodeNonNeg(c[cc.Type].(uint64))
				if err != nil {
					return
				}
			}
			face.Add(tlv)
		}
		controlResponse.Add(face)
	}

	d = &Data{}
	d.Content, err = controlResponse.Encode()
	return
}

const (
	FIB_STATUS uint8 = iota
	FACE_STATUS
	FORWARDER_STATUS
)

func bodyType(l []TLV) uint8 {
	if len(l) == 0 {
		return FORWARDER_STATUS
	}
	for _, c := range l {
		if c.Type != FIB_ENTRY {
			return FORWARDER_STATUS
		}
	}
	if l[0].Children[0].Type == FACE_ID {
		return FACE_STATUS
	} else {
		return FIB_STATUS
	}
}

func (this *ControlResponse) Decode(d *Data) error {
	resp, err := match(controlResponseFormat, d.Content)
	if err != nil {
		return err
	}
	this.ForwarderStatus = make(map[uint64]uint64)
	body := bodyType(resp.Children[2:])
	for _, c := range resp.Children {
		switch c.Type {
		case STATUS_CODE:
			this.StatusCode, err = decodeNonNeg(c.Value)
			if err != nil {
				return err
			}
		case STATUS_TEXT:
			this.StatusText = string(c.Value)
		case CONTROL_PARAMETERS:
			err = this.Parameters.decode(c)
			if err != nil {
				return err
			}
		default:
			switch body {
			case FACE_STATUS:
				for _, cc := range c.Children {
					face := FaceEntry{}
					switch cc.Type {
					case LOCAL_URI:
						face[cc.Type] = string(cc.Value)
					default:
						face[cc.Type], err = decodeNonNeg(cc.Value)
						if err != nil {
							return err
						}
					}
					this.FaceStatus = append(this.FaceStatus, face)
				}
			case FORWARDER_STATUS:
				this.ForwarderStatus[c.Type], err = decodeNonNeg(c.Value)
				if err != nil {
					return err
				}
			case FIB_STATUS:
				fib := FibEntry{
					Name: nameDecode(c.Children[0]),
				}
				// next hop
				for _, cc := range c.Children[1:] {
					nextHop := NextHopRecord{}
					nextHop.FaceId, err = decodeNonNeg(cc.Children[0].Value)
					if err != nil {
						return err
					}
					nextHop.Cost, err = decodeNonNeg(cc.Children[1].Value)
					if err != nil {
						return err
					}
					fib.NextHops = append(fib.NextHops, nextHop)
				}
				this.FibStatus = append(this.FibStatus, fib)
			}
		}
	}
	return nil
}
