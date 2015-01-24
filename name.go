package ndn

import (
	"bytes"
	"net/url"
	"strings"

	"github.com/go-ndn/tlv"
)

type Component []byte

type Name struct {
	Components []Component `tlv:"8"`
}

// NewName creates a name from string representation
func NewName(s string) (n Name) {
	s = strings.Trim(s, "/")
	if s == "" {
		return
	}
	cs := strings.Split(s, "/")
	n.Components = make([]Component, len(cs))
	for i := range cs {
		c, _ := url.QueryUnescape(cs[i])
		n.Components[i] = Component(c)
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
	return 0
}

func (this *Name) WriteTo(w tlv.Writer) error {
	return tlv.Marshal(w, this, 7)
}

func (this *Name) ReadFrom(r tlv.PeekReader) error {
	return tlv.Unmarshal(r, this, 7)
}

func (this Name) String() string {
	if len(this.Components) == 0 {
		return "/"
	}
	buf := new(bytes.Buffer)
	for _, c := range this.Components {
		buf.WriteByte('/')
		buf.WriteString(url.QueryEscape(string(c)))
	}
	return buf.String()
}
