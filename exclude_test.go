package ndn

import (
	"reflect"
	"testing"
)

type excludeTest struct {
	in   string
	want bool
}

func TestExclude(t *testing.T) {
	e1 := NewExclude(nil, Component("AB"))

	for _, test := range []excludeTest{
		{"AB", true},
		{"AA", true},
		{"ABC", false},
	} {
		got := e1.Match(Component(test.in))
		if got != test.want {
			t.Fatalf("..AB Match(%s) == %v, got %v", test.in, test.want, got)
		}
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
