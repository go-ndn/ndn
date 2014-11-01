package ndn

import (
	"bytes"
	"encoding/hex"
	"net/url"
	"strings"
)

type Component []byte

type Name struct {
	Components []Component `tlv:"8"`
	Digest     Component   `tlv:"1!"`
}

// NewName creates a name from string representation
func NewName(s string) (n Name) {
	s = strings.Trim(s, "/")
	if s == "" {
		return
	}
	for _, c := range strings.Split(s, "/") {
		uc, _ := url.QueryUnescape(c)
		n.Components = append(n.Components, Component(uc))
	}
	return
}

// Compare compares two names according to http://named-data.net/doc/ndn-tlv/name.html#canonical-order
//
// -1 if a < b; 0 if a == b; 1 if a > b
func (this *Name) Compare(n Name) int {
	for i := 0; i < len(this.Components) && i < len(n.Components); i++ {
		cmp := bytes.Compare(this.Components[i], n.Components[i])
		if cmp != 0 {
			return cmp
		}
	}
	if len(this.Components) < len(n.Components) {
		return -1
	}
	if len(this.Components) > len(n.Components) {
		return 1
	}
	return bytes.Compare(this.Digest, n.Digest)
}

func (this *Name) CertificateName() (name Name) {
	if len(this.Components) < 2 {
		return
	}
	name.Components = append(this.Components[:len(this.Components)-2],
		Component("KEY"),
		this.Components[len(this.Components)-2], this.Components[len(this.Components)-1],
		Component("ID-CERT"))
	return
}

func (this Name) String() (name string) {
	if len(this.Components) == 0 {
		return "/"
	}
	for _, c := range this.Components {
		name += "/" + url.QueryEscape(string(c))
	}
	if len(this.Digest) != 0 {
		name += "/sha256digest=" + hex.EncodeToString(this.Digest)
	}
	return
}
