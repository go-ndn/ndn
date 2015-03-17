package ndn

import (
	"bytes"

	"github.com/go-ndn/tlv"
)

type excluded struct {
	Component Component
	Any       bool //right
}

type Exclude struct {
	list []excluded
}

func (ex *Exclude) UnmarshalBinary(data []byte) error {
	buf := tlv.NewReader(bytes.NewReader(data))
	ex.list = nil
	var e excluded
	if nil == tlv.Unmarshal(buf, &e.Any, 19) {
		ex.list = append(ex.list, e)
	}
	for {
		var e excluded
		if nil != tlv.Unmarshal(buf, &e.Component, 8) {
			break
		}
		tlv.Unmarshal(buf, &e.Any, 19)
		ex.list = append(ex.list, e)
	}
	return nil
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

func (ex *Exclude) MarshalBinary() (data []byte, err error) {
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
	data = buf.Bytes()
	return
}
