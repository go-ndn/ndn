package ndn

import (
	"errors"
	"time"
)

/*
   Interact with NFD
   should be fine if you remove this file
*/

const (
	STATUS_CODE_OK             uint64 = 200
	STATUS_CODE_ARGS_INCORRECT        = 400
	STATUS_CODE_NOT_AUTHORIZED        = 403
	STATUS_CODE_NOT_FOUND             = 404
	STATUS_CODE_NOT_SUPPORTED         = 501
)

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
)

var (
	controlResponseFormat = node{Type: CONTROL_RESPONSE, Children: []node{
		{Type: STATUS_CODE},
		{Type: STATUS_TEXT},
		// body
	}}
	controlParametersFormat = node{Type: CONTROL_PARAMETERS, Children: []node{
		{Type: NAME, Children: []node{{Type: NAME_COMPONENT, Count: ZERO_OR_MORE}}},
		{Type: FACE_ID, Count: ZERO_OR_ONE},
		{Type: URI, Count: ZERO_OR_ONE},
		{Type: LOCAL_CONTROL_FEATURE, Count: ZERO_OR_ONE},
		{Type: COST, Count: ZERO_OR_ONE},
		{Type: STRATEGY, Count: ZERO_OR_ONE, Children: []node{
			{Type: NAME, Children: []node{{Type: NAME_COMPONENT, Count: ZERO_OR_MORE}}},
		}},
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

func (this *Control) Encode() (raw []byte, err error) {
	name := [][]byte{[]byte("localhost"), []byte("nfd"), []byte(this.Module), []byte(this.Command)}

	parameters := NewTLV(CONTROL_PARAMETERS)
	// name
	if len(this.Parameters.Name) != 0 {
		parameters.Add(nameEncode(this.Parameters.Name))
	}
	// face id
	if this.Parameters.FaceId != 0 {
		faceId := NewTLV(FACE_ID)
		faceId.Value, err = encodeNonNeg(this.Parameters.FaceId)
		if err != nil {
			return
		}
		parameters.Add(faceId)
	}
	// uri
	if len(this.Parameters.Uri) != 0 {
		uri := NewTLV(URI)
		uri.Value = []byte(this.Parameters.Uri)
		parameters.Add(uri)
	}
	// local control feature
	if this.Parameters.LocalControlFeature != 0 {
		localControlFeature := NewTLV(LOCAL_CONTROL_FEATURE)
		localControlFeature.Value, err = encodeNonNeg(this.Parameters.LocalControlFeature)
		if err != nil {
			return
		}
		parameters.Add(localControlFeature)
	}
	// cost
	if this.Parameters.Cost != 0 {
		cost := NewTLV(COST)
		cost.Value, err = encodeNonNeg(this.Parameters.Cost)
		if err != nil {
			return
		}
		parameters.Add(cost)
	}
	// strategy
	if len(this.Parameters.Strategy) != 0 {
		strategy := NewTLV(STRATEGY)
		strategy.Add(nameEncode(this.Parameters.Strategy))
		parameters.Add(strategy)
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
	name = append(name, append([]byte{0xFE}, NewNonce()...))

	// signature info
	signatureInfo := NewTLV(SIGNATURE_INFO)
	// signature type
	signatureType := NewTLV(SIGNATURE_TYPE)
	signatureType.Value, err = encodeNonNeg(SIGNATURE_TYPE_DIGEST_SHA_256)
	if err != nil {
		return
	}
	signatureInfo.Add(signatureType)
	b, err = signatureInfo.Encode()
	if err != nil {
		return
	}
	name = append(name, b)

	// signature value
	tlv := nameEncode(name)
	signatureValue := NewTLV(SIGNATURE_VALUE)
	signatureValue.Value, err = NewSHA256(tlv.Children)
	if err != nil {
		return
	}
	b, err = signatureValue.Encode()
	if err != nil {
		return
	}
	name = append(name, b)

	// final encode
	interest := NewInterest("")
	interest.Name = name
	raw, err = interest.Encode()
	return
}

type ControlResponse struct {
	StatusCode uint64
	StatusText string
}

func DecodeControlResponse(raw []byte) (data TLV, err error) {
	data, err = DecodeData(raw)
	if err != nil {
		return
	}
	// children 3 is content
	resp, remain, err := matchNode(controlParametersFormat, data.Children[2].Value)
	if err != nil {
		return
	}
	if len(remain) != 0 {
		err = errors.New(BUFFER_NOT_EMPTY)
	}
	data.Children[2].Value = nil
	data.Children[2].Add(resp)
	return
}

func (this *ControlResponse) Decode(raw []byte) error {
	data, err := DecodeControlResponse(raw)
	if err != nil {
		return err
	}
	resp := data.Children[2].Children[0]
	for _, c := range resp.Children {
		switch c.Type {
		case STATUS_CODE:
			this.StatusCode, err = decodeNonNeg(c.Value)
			if err != nil {
				return err
			}
		case STATUS_TEXT:
			this.StatusText = string(c.Value)
		}
	}
	return nil
}
