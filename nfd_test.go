package ndn

import (
	//"bytes"
	"testing"
)

func TestControl(t *testing.T) {
	control := Control{
		Module:  "faces",
		Command: "create",
		Parameters: Parameters{
			Uri: "localhost:4000",
		},
	}
	_, err := control.Interest()
	if err != nil {
		t.Error(err)
	}
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
