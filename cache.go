package ndn

import (
	"container/list"
	"sync"
	"time"

	"github.com/go-ndn/lpm"
)

var (
	// ContentStore is the default in-memory storage for data packets
	ContentStore = NewCache(65536)
)

// Cache stores data packet and finds data packet by interest
type Cache interface {
	Add(*Data)
	Get(*Interest) *Data
}

// NewCache creates a new thread-safe in-memory LRU content store
func NewCache(size int) Cache {
	return &cache{
		Matcher: lpm.New(),
		List:    list.New(),
		size:    size,
	}
}

type cache struct {
	lpm.Matcher
	*list.List
	size int
	sync.Mutex
}

type cacheEntry struct {
	*Data
	time.Time
	remove func()
}

func (c *cache) Add(d *Data) {
	c.Lock()
	defer c.Unlock()

	name := d.Name.String()

	// check for existing element
	var exist bool
	c.Match(name, func(v interface{}) {
		if v == nil {
			return
		}
		if elem, ok := v.(map[string]*list.Element)[name]; ok {
			c.MoveToFront(elem)
			exist = true
		}
	}, false)
	if exist {
		return
	}

	// add new element
	elem := c.PushFront(cacheEntry{
		Data: d,
		Time: time.Now(),
		remove: func() {
			c.UpdateAll(name, func(_ []byte, v interface{}) interface{} {
				if v == nil {
					return nil
				}
				m := v.(map[string]*list.Element)
				delete(m, name)
				if len(m) == 0 {
					return nil
				}
				return m
			}, false)
		},
	})
	c.UpdateAll(name, func(_ []byte, v interface{}) interface{} {
		var m map[string]*list.Element
		if v == nil {
			m = make(map[string]*list.Element)
		} else {
			m = v.(map[string]*list.Element)
		}
		m[name] = elem
		return m
	}, false)

	// evict oldest element
	if c.Len() <= c.size {
		return
	}
	elem = c.Back()
	if elem == nil {
		return
	}
	c.Remove(elem).(cacheEntry).remove()
}

func (c *cache) Get(i *Interest) *Data {
	c.Lock()
	defer c.Unlock()

	var match *list.Element
	c.MatchRaw(i.Name.Components, func(v interface{}) {
		if v == nil {
			return
		}
		for _, elem := range v.(map[string]*list.Element) {
			ent := elem.Value.(cacheEntry)
			if !i.Selectors.Match(ent.Data, i.Name.Len()) {
				continue
			}
			if i.Selectors.MustBeFresh && time.Since(ent.Time) > time.Duration(ent.MetaInfo.FreshnessPeriod)*time.Millisecond {
				continue
			}
			if match == nil {
				match = elem
			} else {
				cmp := ent.Name.Compare(match.Value.(cacheEntry).Name)
				switch i.Selectors.ChildSelector {
				case 0:
					if cmp < 0 {
						match = elem
					}
				case 1:
					if cmp > 0 {
						match = elem
					}
				}
			}
		}
	}, false)
	if match != nil {
		c.MoveToFront(match)
		return match.Value.(cacheEntry).Data
	}
	return nil
}
