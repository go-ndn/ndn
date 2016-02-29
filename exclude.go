package ndn

import (
	"bytes"

	"github.com/go-ndn/lpm"
	"github.com/go-ndn/tlv"
)

// Interval is part of an Exclude list.
//
// If none of the Any components are specified, the filter excludes only to the names specified in the Exclude list.
//
// If a leading Any component is specified, then the filter excludes all names that are smaller or equal (in NDN name component canonical ordering) to the first NameComponent in the Exclude list.
//
// If a trailing Any component is specified, then the filter excludes all names that are larger or equal (in NDN name component canonical ordering) to the last NameComponent in the Exclude list.
//
// If Any component is specified between two NameComponents in the list, then the filter excludes all names from the range from the right NameComponent to the left NameComponent, including both ends.
type Interval struct {
	lpm.Component
	Any bool // Component..?
}

// Exclude allows requester to specify list and/or ranges of names components
// that MUST NOT appear as a continuation of the Name prefix in the responding Data packet to the Interest.
//
// See http://named-data.net/doc/ndn-tlv/interest.html#exclude.
type Exclude []Interval

// Match checks whether the given component is in the intervals.
func (ex Exclude) Match(c lpm.Component) bool {
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

// UnmarshalBinary decodes Exclude tlv-encoded data.
//
// Exclude is a special case in tlv package.
// It needs to implement encoding.BinaryUnmarshaler to unmarshal
// a binary representation of itself.
func (ex *Exclude) UnmarshalBinary(b []byte) (err error) {
	r := tlv.NewReader(bytes.NewReader(b))
	for {
		switch r.Peek() {
		case 19:
			if len(*ex) == 0 {
				*ex = append(*ex, Interval{})
			}
			err = r.Read(&(*ex)[len(*ex)-1].Any, 19)
			if err != nil {
				return
			}
		case 8:
			var intv Interval
			err = r.Read(&intv.Component, 8)
			if err != nil {
				return
			}
			*ex = append(*ex, intv)
		default:
			return
		}
	}
}

// MarshalBinary encodes Exclude in tlv.
//
// Exclude is a special case in tlv package.
// It needs to implement encoding.BinaryMarshaler to marshal itself
// into a binary form.
func (ex Exclude) MarshalBinary() (b []byte, err error) {
	buf := new(bytes.Buffer)
	w := tlv.NewWriter(buf)
	for _, intv := range ex {
		if len(intv.Component) != 0 {
			err = w.Write(intv.Component, 8)
			if err != nil {
				return
			}
		}
		err = w.Write(intv.Any, 19)
		if err != nil {
			return
		}
	}
	b = buf.Bytes()
	return
}
