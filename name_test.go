package ndn

import "testing"

func TestName(t *testing.T) {
	name := NewName("/A/B")
	if 0 != name.Compare(NewName("/A/B")) {
		t.Fatal("want /A/B = /A/B")
	}

	if -1 != name.Compare(NewName("/A/C")) {
		t.Fatal("want /A/B < /A/C")
	}

	if 1 != name.Compare(NewName("/A/A")) {
		t.Fatal("want /A/B > /A/A")
	}

	if -1 != name.Compare(NewName("/A/B/C")) {
		t.Fatal("want /A/B < /A/B/C")
	}

	if 1 != name.Compare(NewName("/A")) {
		t.Fatal("want /A/B > /A")
	}
}
