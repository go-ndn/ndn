package ndn

import (
	"reflect"

	"github.com/go-ndn/tlv"
)

func init() {
	// zero-allocation tlv
	tlv.CacheType(reflect.TypeOf((*Interest)(nil)))
	tlv.CacheType(reflect.TypeOf((*Data)(nil)))
	tlv.CacheType(reflect.TypeOf((*Command)(nil)))
	tlv.CacheType(reflect.TypeOf((*ControlResponse)(nil)))
}
