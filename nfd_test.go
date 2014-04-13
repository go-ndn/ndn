package ndn

import (
	//"bytes"
	//"github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"os"
	"testing"
)

func TestControl(t *testing.T) {
	f, err := os.Open("key/testing.pri")
	if err != nil {
		t.Error(err)
		return
	}
	defer f.Close()
	b, err := ioutil.ReadAll(f)
	if err != nil {
		t.Error(err)
		return
	}

	key, err := ReadRSAKey(b)
	if err != nil {
		t.Error(err)
		return
	}
	SignKey = key
	VerifyKey = key

	control := Control{
		Module:  "faces",
		Command: "create",
		Parameters: Parameters{
			Uri: "tcp://localhost:4000",
		},
	}
	i, err := control.Encode()
	if err != nil {
		t.Error(err)
		return
	}
	control2 := Control{}
	err = control2.Decode(i)
	if err != nil {
		t.Error(err)
		return
	}
	face, err := NewFace("tcp://localhost:6363")
	if err != nil {
		t.Error(err)
		return
	}
	d, err := face.Dial(i)
	if err != nil {
		return
	}
	cr := ControlResponse{}
	err = cr.Decode(d)
	if err != nil {
		t.Error(err)
		return
	}
	//spew.Dump(cr)
}

func TestControlResponse(t *testing.T) {
	resp := ControlResponse{
		StatusCode: 200,
		StatusText: "system online",
		Parameters: Parameters{
			Name: nameFromString("/system/ok"),
			Cost: 400,
		},
	}
	d, err := resp.Encode()
	if err != nil {
		t.Error(err)
		return
	}
	resp2 := ControlResponse{}
	err = resp2.Decode(d)
	if err != nil {
		t.Error(err)
		return
	}
	if resp2.StatusCode != 200 {
		t.Errorf("expected %v, got %v", 200, resp2.StatusCode)
		return
	}

	if resp2.StatusText != "system online" {
		t.Errorf("expected %v, got %v", "system online", resp2.StatusText)
		return
	}
	if resp2.Parameters.Cost != 400 {
		t.Errorf("expected %v, got %v", 400, resp2.Parameters.Cost)
		return
	}
	if nameToString(resp2.Parameters.Name) != "/system/ok" {
		t.Errorf("expected %v, got %v", "/system/ok", resp2.Parameters.Name)
		return
	}
}
