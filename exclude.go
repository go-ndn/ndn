package ndn

import (
	"bytes"
	"github.com/taylorchu/tlv"
)

type excluded struct {
	Component Component
	Any       bool //right
}

type Exclude struct {
	excluded []excluded
}

func (this *Exclude) ReadValueFrom(r tlv.PeekReader) error {
	this.excluded = []excluded{{Component: Component{}}}
	for {
		if nil == tlv.Unmarshal(r, &this.excluded[len(this.excluded)-1].Any, 19) {
			continue
		}
		var c Component
		if nil == tlv.Unmarshal(r, &c, 8) {
			this.excluded = append(this.excluded, excluded{Component: c})
			continue
		}
		break
	}
	return nil
}

func (this *Exclude) IsExcluded(c Component) bool {
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

func (this *Exclude) WriteValueTo(buf tlv.Writer) (err error) {
	for _, e := range this.excluded {
		if len(e.Component) != 0 {
			err = tlv.Marshal(buf, e.Component, 8)
			if err != nil {
				return
			}
		}
		if e.Any {
			err = tlv.Marshal(buf, e.Any, 19)
			if err != nil {
				return
			}
		}
	}
	return
}
