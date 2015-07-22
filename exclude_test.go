package ndn

import (
	"reflect"
	"testing"
)

func TestExclude(t *testing.T) {
	ex1 := Exclude{
		{Any: true},
		{Component: Component("AB")},
	}

	for _, test := range []struct {
		in   string
		want bool
	}{
		{"AB", true},
		{"AA", true},
		{"ABC", false},
	} {
		got := ex1.Match(Component(test.in))
		if got != test.want {
			t.Fatalf("Match(%v) == %v, got %v", test.in, test.want, got)
		}
	}

	b, err := ex1.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var ex2 Exclude
	err = ex2.UnmarshalBinary(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ex1, ex2) {
		t.Fatal("not equal", ex1, ex2)
	}
}
