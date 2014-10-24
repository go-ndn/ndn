package ndn

import (
	"bufio"
	"bytes"
	"reflect"
	"testing"
)

func TestExclude(t *testing.T) {
	e1 := NewExclude(nil, Component("AB"))
	if len(e1.excluded) != 2 {
		t.Fatal("should have 2 components")
	}
	if !e1.Match(Component("AB")) {
		t.Fatal("should be excluded")
	}
	if !e1.Match(Component("AA")) {
		t.Fatal("should be excluded")
	}
	if e1.Match(Component("ABC")) {
		t.Fatal("should not be excluded")
	}

	buf := new(bytes.Buffer)
	err := e1.WriteValueTo(buf)
	if err != nil {
		t.Fatal(err)
	}
	var e2 Exclude
	e2.ReadValueFrom(bufio.NewReader(buf))
	if !reflect.DeepEqual(e1, e2) {
		t.Fatal("not equal", e1, e2)
	}
}
