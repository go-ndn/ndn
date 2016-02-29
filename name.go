package ndn

import (
	"bytes"
	"net/url"
	"strings"

	"github.com/go-ndn/lpm"
	"github.com/go-ndn/tlv"
)

// Name is a hierarchical name for NDN content, which contains a sequence of name components.
type Name struct {
	Components []lpm.Component `tlv:"8"`
}

// NewName creates a name from percent-encoded form.
func NewName(s string) (n Name) {
	s = strings.Trim(s, "/")
	if s == "" {
		return
	}
	parts := strings.Split(s, "/")
	n.Components = make([]lpm.Component, len(parts))
	for i := range parts {
		parts[i], _ = url.QueryUnescape(parts[i])
		n.Components[i] = lpm.Component(parts[i])
	}
	return
}

// Compare compares two names according to http://named-data.net/doc/ndn-tlv/name.html#canonical-order.
//
// -1 if a < b; 0 if a == b; 1 if a > b
func (n *Name) Compare(n2 Name) int {
	l1, l2 := n.Len(), n2.Len()
	for i := 0; i < l1 && i < l2; i++ {
		cmp := bytes.Compare(n.Components[i], n2.Components[i])
		if cmp != 0 {
			return cmp
		}
	}
	if l1 < l2 {
		return -1
	}
	if l1 > l2 {
		return 1
	}
	return 0
}

// Len returns the number of components.
func (n *Name) Len() int {
	return len(n.Components)
}

// WriteTo implements tlv.WriteTo
func (n *Name) WriteTo(w tlv.Writer) error {
	return w.Write(n, 7)
}

// ReadFrom implements tlv.ReadFrom
func (n *Name) ReadFrom(r tlv.Reader) error {
	return r.Read(n, 7)
}

func (n Name) String() string {
	buf := new(bytes.Buffer)
	for _, c := range n.Components {
		buf.WriteByte('/')
		buf.WriteString(c.String())
	}
	return buf.String()
}
