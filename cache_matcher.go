package ndn

import (
	"container/list"
	"github.com/go-ndn/lpm"
)

type cacheMatcher struct{ cacheNode }
type cacheNode struct {
	val   *map[string]*list.Element
	table map[string]*cacheNode
}

func (n *cacheNode) Empty() bool {
	return n.val == nil && len(n.table) == 0
}
func cacheDeref(val *map[string]*list.Element) (map[string]*list.Element, bool) {
	if val == nil {
		var t map[string]*list.Element
		return t, false
	}
	return *val, true
}
func (n *cacheNode) Match(key []lpm.Component) (val map[string]*list.Element, found bool) {
	if len(key) == 0 {
		return cacheDeref(n.val)
	}
	if n.table == nil {
		return cacheDeref(n.val)
	}
	child, ok := n.table[string(key[0])]
	if !ok {
		return cacheDeref(n.val)
	}
	return child.Match(key[1:])
}
func (n *cacheNode) Get(key []lpm.Component) (val map[string]*list.Element, found bool) {
	if len(key) == 0 {
		return cacheDeref(n.val)
	}
	if n.table == nil {
		return cacheDeref(nil)
	}
	child, ok := n.table[string(key[0])]
	if !ok {
		return cacheDeref(nil)
	}
	return child.Get(key[1:])
}
func (n *cacheNode) Update(key []lpm.Component, val map[string]*list.Element) {
	if len(key) == 0 {
		n.val = &val
		return
	}
	if n.table == nil {
		n.table = make(map[string]*cacheNode)
	}
	if _, ok := n.table[string(key[0])]; !ok {
		n.table[string(key[0])] = &cacheNode{}
	}
	n.table[string(key[0])].Update(key[1:], val)
}
func (n *cacheNode) Delete(key []lpm.Component) {
	if len(key) == 0 {
		n.val = nil
		return
	}
	if n.table == nil {
		return
	}
	child, ok := n.table[string(key[0])]
	if !ok {
		return
	}
	child.Delete(key[1:])
	if child.Empty() {
		delete(n.table, string(key[0]))
	}
}

type cacheUpdateFunc func([]lpm.Component, map[string]*list.Element) (val map[string]*list.Element, del bool)

func (n *cacheNode) UpdateAll(key []lpm.Component, f cacheUpdateFunc) {
	for i := len(key); i > 0; i-- {
		k := key[:i]
		val, _ := n.Get(k)
		val2, del := f(k, val)
		if !del {
			n.Update(k, val2)
		} else {
			n.Delete(k)
		}
	}
}
func (n *cacheNode) visit(key []lpm.Component, f func([]lpm.Component)) {
	for k, v := range n.table {
		v.visit(append(key, lpm.Component(k)), f)
	}
	if n.val != nil {
		f(key)
	}
}
func (n *cacheNode) Visit(f cacheUpdateFunc) {
	n.visit(make([]lpm.Component, 0, 16), func(k []lpm.Component) {
		val, found := n.Get(k)
		if found {
			val2, del := f(k, val)
			if !del {
				n.Update(k, val2)
			} else {
				n.Delete(k)
			}
		}
	})
}
