package ndn

import (
	"bytes"
	//"fmt"
	"encoding/json"
	"testing"
)

func TestData(t *testing.T) {
	data := NewData("/google/search")
	data.MetaInfo.ContentType = 2
	data.MetaInfo.FreshnessPeriod = 3
	data.MetaInfo.FinalBlockId = []byte("hello")
	data.Content = []byte{0x1, 0x2, 0x3}

	data.Signature.Type = 1
	data.Signature.Value = []byte{0x1, 0x2, 0x3}

	b, err := data.Encode()
	if err != nil {
		t.Error(err)
	}

	data_decode := Data{}
	err = data_decode.Decode(b)
	if err != nil {
		t.Error(err)
	}
	// name order changes
	data.Name = nil
	data_decode.Name = nil
	b1, err := json.Marshal(data)
	if err != nil {
		t.Error(err)
	}
	b2, err := json.Marshal(data_decode)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Errorf("expected %v, got %v", b1, b2)
	}
}

func TestInterest(t *testing.T) {
	interest := NewInterest("/facebook/users")

	interest.Selectors.MinSuffixComponents = 3
	interest.Selectors.MaxSuffixComponents = 5
	interest.Selectors.ChildSelector = 4
	interest.Selectors.MustBeFresh = true
	interest.Scope = 8
	interest.InterestLifeTime = 9
	interest.Nonce = []byte{0x1, 0x2, 0x3}
	b, err := interest.Encode()
	if err != nil {
		t.Error(err)
	}

	interest_decode := Interest{}
	err = interest_decode.Decode(b)
	if err != nil {
		t.Error(err)
	}
	// name order changes
	interest.Name = nil
	interest_decode.Name = nil
	b1, err := json.Marshal(interest)
	if err != nil {
		t.Error(err)
	}
	b2, err := json.Marshal(interest_decode)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Errorf("expected %v, got %v", b1, b2)
	}
}
