package ndn

import (
	"bytes"

	"github.com/go-ndn/tlv"
)

type excluded struct {
	Component Component
	Any       bool // Component..?
}

type Exclude struct {
	list []excluded
}

func (ex *Exclude) UnmarshalBinary(b []byte) (err error) {
	ex.list = nil
	buf := tlv.NewReader(bytes.NewReader(b))
	for {
		switch buf.Peek() {
		case 19:
			if len(ex.list) == 0 {
				ex.list = []excluded{{}}
			}
			err = tlv.Unmarshal(buf, &ex.list[len(ex.list)-1].Any, 19)
			if err != nil {
				return
			}
		case 8:
			var e excluded
			err = tlv.Unmarshal(buf, &e.Component, 8)
			if err != nil {
				return
			}
			ex.list = append(ex.list, e)
		default:
			return
		}
	}
}

func (ex *Exclude) Match(c Component) bool {
	for i := len(ex.list) - 1; i >= 0; i-- {
		cmp := bytes.Compare(ex.list[i].Component, c)
		if cmp == 0 {
			return true
		}
		if cmp < 0 {
			return ex.list[i].Any
		}
	}
	return false
}

func NewExclude(cs ...Component) (ex Exclude) {
	for _, c := range cs {
		if c == nil {
			if len(ex.list) == 0 {
				ex.list = []excluded{{}}
			}
			ex.list[len(ex.list)-1].Any = true
		} else {
			ex.list = append(ex.list, excluded{Component: c})
		}
	}
	return
}

func (ex *Exclude) MarshalBinary() (b []byte, err error) {
	buf := new(bytes.Buffer)
	for _, e := range ex.list {
		if len(e.Component) != 0 {
			err = tlv.Marshal(buf, e.Component, 8)
			if err != nil {
				return
			}
		}
		err = tlv.Marshal(buf, e.Any, 19)
		if err != nil {
			return
		}
	}
	b = buf.Bytes()
	return
}
