package ndn

import (
	"time"

	"github.com/go-ndn/lpm"
)

var (
	ContentStore = NewCache()
)

type Cache struct {
	lpm.Matcher
}

func NewCache() *Cache {
	return &Cache{Matcher: lpm.NewThreadSafe()}
}

func (c *Cache) Add(d *Data) {
	t := time.Now()
	c.UpdateAll(d.Name.String(), func(_ string, v interface{}) interface{} {
		var m map[*Data]time.Time
		if v == nil {
			m = make(map[*Data]time.Time)
		} else {
			m = v.(map[*Data]time.Time)
		}
		m[d] = t
		return m
	}, false)
}

func (c *Cache) Get(i *Interest) (cache *Data) {
	name := i.Name.String()
	c.Match(name, func(v interface{}) {
		var m map[*Data]time.Time
		if v == nil {
			m = make(map[*Data]time.Time)
		} else {
			m = v.(map[*Data]time.Time)
		}
		for d, t := range m {
			if i.Selectors.Match(name, d, t) {
				if cache == nil || d.Name.Compare(cache.Name) < 0 {
					cache = d
				}
			}
		}
	}, false)
	return
}
