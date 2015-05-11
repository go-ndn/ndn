package ndn

import "testing"

func TestCache(t *testing.T) {
	c := NewCache(3)

	for _, test := range []string{
		"/A/B",
		"/A",
		"/A",
		"/A/B/C",
		"/B",
	} {
		d := &Data{
			Name: NewName(test),
		}
		c.Add(d)
	}
	for _, test := range []struct {
		in   string
		want string
	}{
		{"/A", "/A/B/C"},
		{"/A/B", "/A/B/C"},
		{"/C", ""},
	} {
		d := c.Get(&Interest{
			Name: NewName(test.in),
			Selectors: Selectors{
				ChildSelector: 1,
			},
		})
		var got string
		if d != nil {
			got = d.Name.String()
		}
		if got != test.want {
			t.Fatalf("Cache.Get(%s) == %v, got %v", test.in, test.want, got)
		}
	}
}
