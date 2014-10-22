package ndn

import (
	"bufio"
	"bytes"
	"reflect"
	"testing"
)

func TestExclude(t *testing.T) {
	b := bytes.NewBuffer([]byte{
		19, 0, 8, 2, 'A', 'B',
	})
	var e1 Exclude
	e1.ReadValueFrom(bufio.NewReader(b))
	if len(e1.excluded) != 2 {
		t.Fatal("should have 2 components")
	}
	if !e1.IsExcluded(Component("AB")) {
		t.Fatal("should be excluded")
	}
	if !e1.IsExcluded(Component("AA")) {
		t.Fatal("should be excluded")
	}
	if e1.IsExcluded(Component("ABC")) {
		t.Fatal("should not be excluded")
	}

	err := e1.WriteValueTo(b)
	if err != nil {
		t.Fatal(err)
	}
	var e2 Exclude
	e2.ReadValueFrom(bufio.NewReader(b))
	if !reflect.DeepEqual(e1, e2) {
		t.Fatal("not equal", e1, e2)
	}
}
