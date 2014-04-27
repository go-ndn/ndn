package ndn

import (
	//"bytes"
	"github.com/davecgh/go-spew/spew"
	"testing"
)

func TestEncoding(t *testing.T) {
	face, err := NewFace("tcp://localhost:6363")
	if err != nil {
		t.Error(err)
	}
	d := new(ForwarderStatusPacket)
	err = face.Dial(NewInterest("/localhost/nfd/status"), d)
	if err != nil {
		t.Error(err)
	}
	spew.Dump(d)
}
