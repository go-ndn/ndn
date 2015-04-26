package ndn

import (
	"container/list"
	"sync"
	"time"

	"github.com/go-ndn/lpm"
)

var (
	ContentStore = NewCache(1000)
)

type Cache interface {
	Add(*Data)
	Get(*Interest) *Data
}

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
	mu   sync.Mutex
}

type entry struct {
	data *Data
	time time.Time
}

func (c *cache) Add(d *Data) {
	c.mu.Lock()
	defer c.mu.Unlock()

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
	elem := c.PushFront(entry{
		data: d,
		time: time.Now(),
	})
	c.UpdateAll(name, func(_ string, v interface{}) interface{} {
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
	name = c.Remove(elem).(entry).data.Name.String()
	c.UpdateAll(name, func(_ string, v interface{}) interface{} {
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
}

func (c *cache) Get(i *Interest) *Data {
	c.mu.Lock()
	defer c.mu.Unlock()

	var match *list.Element
	name := i.Name.String()
	c.Match(name, func(v interface{}) {
		if v == nil {
			return
		}
		for _, elem := range v.(map[string]*list.Element) {
			ent := elem.Value.(entry)
			if !i.Selectors.Match(name, ent.data, ent.time) {
				continue
			}
			if match == nil {
				match = elem
			} else {
				cmp := ent.data.Name.Compare(match.Value.(entry).data.Name)
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
		return match.Value.(entry).data
	}
	return nil
}
