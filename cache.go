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

type record struct {
	data *Data
	time time.Time
}

func (c *Cache) Add(d *Data) {
	c.Update(d.Name.String(), func(v interface{}) interface{} {
		if v != nil {
			return v
		}
		return record{
			data: d,
			time: time.Now(),
		}
	})
}

func (c *Cache) Get(i *Interest) (cache *Data) {
	name := i.Name.String()
	c.Match(name, func(v interface{}) {
		if v == nil {
			return
		}
		r := v.(record)
		if i.Selectors.Match(name, r.data, r.time) {
			cache = r.data
		}
	})
	return
}
