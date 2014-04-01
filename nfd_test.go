package ndn

import (
	//"bytes"
	"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"os"
	"testing"
)

func TestControl(t *testing.T) {
	f, err := os.Open("key/testing.pri")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	b, err := ioutil.ReadAll(f)
	if err != nil {
		t.Error(err)
	}

	err = ReadRSAKey(b)
	if err != nil {
		t.Error(err)
	}

	control := Control{
		Module:  "faces",
		Command: "create",
		Parameters: Parameters{
			Uri: "localhost:4000",
		},
	}
	i, err := control.Interest()
	if err != nil {
		t.Error(err)
	}
	d, err := NewFace("localhost").Dial(i)
	if err != nil {
		t.Error(err)
	}
	cr := ControlResponse{}
	err = cr.Data(d)
	if err != nil {
		t.Error(err)
	}
	spew.Dump(cr)
}

func TestControlResponse(t *testing.T) {
	resp := NewTLV(CONTROL_RESPONSE)

	statusCode := NewTLV(STATUS_CODE)
	statusCode.Value, _ = encodeNonNeg(200)
	resp.Add(statusCode)

	statusText := NewTLV(STATUS_TEXT)
	statusText.Value = []byte("system online")
	resp.Add(statusText)

	d := NewData("/nfd")
	d.Content, _ = resp.Encode()

	resp2 := ControlResponse{}
	err := resp2.Data(d)
	if err != nil {
		t.Error(err)
	}
	if resp2.StatusCode != 200 {
		t.Errorf("expected %v, got %v", 200, resp2.StatusCode)
	}

	if resp2.StatusText != "system online" {
		t.Errorf("expected %v, got %v", "system online", resp2.StatusText)
	}
}
