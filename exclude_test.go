package ndn

import "testing"

func TestExclude(t *testing.T) {
	ex := Exclude{
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
		got := ex.Match(Component(test.in))
		if got != test.want {
			t.Fatalf("..AB Match(%v) == %v, got %v", test.in, test.want, got)
		}
	}
}
