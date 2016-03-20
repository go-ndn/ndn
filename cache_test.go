package ndn

import "testing"

func TestCache(t *testing.T) {
	c := NewCache(5)

	for _, test := range []string{
		"/A/B",
		"/A",
		"/A",
		"/A/B/C",
		"/A/C",
		"/BB",
		"/D/E",
	} {
		c.Add(&Data{
			Name: NewName(test),
		})
	}
	for _, test := range []struct {
		in            string
		want          string
		childSelector uint64
		digestSHA256  []byte
	}{
		{
			in:            "/A",
			want:          "/A",
			childSelector: 1,
			digestSHA256:  []byte{0xb8, 0x58, 0x3b, 0xf2, 0x4f, 0xd0, 0xcd, 0x1a, 0x64, 0xb6, 0x71, 0xc7, 0x67, 0x7f, 0x9, 0x89, 0xf4, 0xef, 0xad, 0x54, 0x9a, 0x93, 0xdc, 0x7e, 0x52, 0x31, 0xaa, 0x18, 0x99, 0x96, 0x50, 0x95},
		},
		{
			in:   "/D",
			want: "/D/E",
		},
		{
			in:   "/A",
			want: "/A",
		},
		{
			in:            "/A",
			want:          "/A/C",
			childSelector: 1,
		},
		{
			in:            "/A/B",
			want:          "/A/B/C",
			childSelector: 1,
		},
		{
			in: "/B",
		},
		{
			in: "/C",
		},
	} {
		name := NewName(test.in)
		name.ImplicitDigestSHA256 = test.digestSHA256
		d := c.Get(&Interest{
			Name: name,
			Selectors: Selectors{
				ChildSelector: test.childSelector,
			},
		})
		var got string
		if d != nil {
			got = d.Name.String()
		}
		if got != test.want {
			t.Fatalf("Get(%v) == %v, got %v", test.in, test.want, got)
		}
	}
}
