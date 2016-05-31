package ndn

import (
	"container/list"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/go-ndn/lpm"
	"github.com/go-ndn/tlv"
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
		List: list.New(),
		size: size,
	}
}

type cache struct {
	cacheMatcher
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
	h := sha256.New()
	err := d.WriteTo(tlv.NewWriter(h))
	if err != nil {
		return
	}
	digest := lpm.Component(h.Sum(nil))

	components := append(d.Name.Components, digest)
	key := fmt.Sprintf("%s/%s", d.Name, digest)

	c.Lock()
	defer c.Unlock()
	// check for existing element
	var exist bool
	c.Match(components, func(m map[string]*list.Element) {
		if m == nil {
			return
		}
		if elem, ok := m[key]; ok {
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
			c.UpdateAll(components, func(_ []lpm.Component, m map[string]*list.Element) map[string]*list.Element {
				if m == nil {
					return nil
				}
				delete(m, key)
				if len(m) == 0 {
					return nil
				}
				return m
			}, false)
		},
	})
	c.UpdateAll(components, func(_ []lpm.Component, m map[string]*list.Element) map[string]*list.Element {
		if m == nil {
			m = make(map[string]*list.Element)
		}
		m[key] = elem
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
	components := i.Name.Components
	if len(i.Name.ImplicitDigestSHA256) != 0 {
		components = append(components, i.Name.ImplicitDigestSHA256)
	}

	c.Lock()
	defer c.Unlock()
	var match *list.Element
	c.Match(components, func(m map[string]*list.Element) {
		for _, elem := range m {
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
