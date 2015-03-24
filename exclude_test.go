package ndn

import (
	"reflect"
	"testing"
)

func TestExclude(t *testing.T) {
	e1 := NewExclude(nil, Component("AB"))

	if !e1.Match(Component("AB")) {
		t.Fatal("want AB excluded")
	}
	if !e1.Match(Component("AA")) {
		t.Fatal("want AA excluded")
	}
	if e1.Match(Component("ABC")) {
		t.Fatal("want ABC not excluded")
	}

	b, err := e1.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var e2 Exclude
	e2.UnmarshalBinary(b)
	if !reflect.DeepEqual(e1, e2) {
		t.Fatal("not equal", e1, e2)
	}
}
