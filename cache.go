package ndn

import (
	"time"

	"github.com/go-ndn/exact"
)

var (
	ContentStore = NewCache()
)

type Cache struct {
	*exact.Matcher
}

func NewCache() *Cache {
	return &Cache{Matcher: exact.New()}
}

func (c *Cache) Add(d *Data) {
	c.Update(d.Name.String(), func(v interface{}) interface{} {
		var m map[*Data]time.Time
		if v == nil {
			m = make(map[*Data]time.Time)
		} else {
			m = v.(map[*Data]time.Time)
		}
		m[d] = time.Now()
		return m
	})
}

func (c *Cache) Get(i *Interest) (cache *Data) {
	c.Match(i.Name.String(), func(v interface{}) {
		if v == nil {
			return
		}
		name := i.Name.String()
		for d, t := range v.(map[*Data]time.Time) {
			if i.Selectors.Match(name, d, t) {
				cache = d
				break
			}
		}
	})
	return
}
