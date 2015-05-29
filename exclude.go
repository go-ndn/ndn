package ndn

import "bytes"

type Exclude []struct {
	Component Component `tlv:"8?"`
	Any       bool      `tlv:"19?"` // Component..?
}

func (ex Exclude) Match(c Component) bool {
	for i := len(ex) - 1; i >= 0; i-- {
		cmp := bytes.Compare(ex[i].Component, c)
		if cmp == 0 {
			return true
		}
		if cmp < 0 {
			return ex[i].Any
		}
	}
	return false
}
