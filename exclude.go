package ndn

import (
	"bufio"
	"bytes"

	"github.com/go-ndn/tlv"
)

type excluded struct {
	Component Component
	Any       bool //right
}

type Exclude struct {
	excluded []excluded
}

func (this *Exclude) UnmarshalBinary(data []byte) error {
	buf := bufio.NewReader(bytes.NewReader(data))
	this.excluded = nil
	var e excluded
	if nil == tlv.Unmarshal(buf, &e.Any, 19) {
		this.excluded = append(this.excluded, e)
	}
	for {
		var e excluded
		if nil != tlv.Unmarshal(buf, &e.Component, 8) {
			break
		}
		tlv.Unmarshal(buf, &e.Any, 19)
		this.excluded = append(this.excluded, e)
	}
	return nil
}

func (this *Exclude) Match(c Component) bool {
	for i := len(this.excluded) - 1; i >= 0; i-- {
		cmp := bytes.Compare(this.excluded[i].Component, c)
		if cmp == 0 {
			return true
		}
		if cmp < 0 {
			return this.excluded[i].Any
		}
	}
	return false
}

func NewExclude(cs ...Component) (e Exclude) {
	for _, c := range cs {
		if c == nil {
			if len(e.excluded) == 0 {
				e.excluded = []excluded{{}}
			}
			e.excluded[len(e.excluded)-1].Any = true
		} else {
			e.excluded = append(e.excluded, excluded{Component: c})
		}
	}
	return
}

func (this *Exclude) MarshalBinary() (data []byte, err error) {
	buf := new(bytes.Buffer)
	for _, e := range this.excluded {
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
