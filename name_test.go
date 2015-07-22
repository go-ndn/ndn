package ndn

import "testing"

func TestName(t *testing.T) {
	name := NewName("/A/B")

	for _, test := range []struct {
		in   string
		want int
	}{
		{"/A/B", 0},
		{"/A/C", -1},
		{"/A/A", 1},
		{"/A/B/C", -1},
		{"/A", 1},
	} {
		got := name.Compare(NewName(test.in))
		if got != test.want {
			t.Fatalf("Compare(%v) == %v, got %v", test.in, test.want, got)
		}
	}
}
