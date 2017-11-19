package ndn

import (
	"github.com/go-ndn/lpm"
)

type pitMatcher struct{ pitNode }
type pitNode struct {
	val   *map[chan<- *Data]pitEntry
	table map[string]*pitNode
}

func (n *pitNode) Empty() bool {
	return n.val == nil && len(n.table) == 0
}
func pitDeref(val *map[chan<- *Data]pitEntry) (map[chan<- *Data]pitEntry, bool) {
	if val == nil {
		var t map[chan<- *Data]pitEntry
		return t, false
	}
	return *val, true
}
func (n *pitNode) Match(key []lpm.Component) (val map[chan<- *Data]pitEntry, found bool) {
	if len(key) == 0 {
		return pitDeref(n.val)
	}
	if n.table == nil {
		return pitDeref(n.val)
	}
	child, ok := n.table[string(key[0])]
	if !ok {
		return pitDeref(n.val)
	}
	return child.Match(key[1:])
}
func (n *pitNode) Get(key []lpm.Component) (val map[chan<- *Data]pitEntry, found bool) {
	if len(key) == 0 {
		return pitDeref(n.val)
	}
	if n.table == nil {
		return pitDeref(nil)
	}
	child, ok := n.table[string(key[0])]
	if !ok {
		return pitDeref(nil)
	}
	return child.Get(key[1:])
}
func (n *pitNode) Update(key []lpm.Component, val map[chan<- *Data]pitEntry) {
	if len(key) == 0 {
		n.val = &val
		return
	}
	if n.table == nil {
		n.table = make(map[string]*pitNode)
	}
	if _, ok := n.table[string(key[0])]; !ok {
		n.table[string(key[0])] = &pitNode{}
	}
	n.table[string(key[0])].Update(key[1:], val)
}
func (n *pitNode) Delete(key []lpm.Component) {
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

type pitUpdateFunc func([]lpm.Component, map[chan<- *Data]pitEntry) (val map[chan<- *Data]pitEntry, del bool)

func (n *pitNode) UpdateAll(key []lpm.Component, f pitUpdateFunc) {
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
func (n *pitNode) visit(key []lpm.Component, f func([]lpm.Component)) {
	for k, v := range n.table {
		v.visit(append(key, lpm.Component(k)), f)
	}
	if n.val != nil {
		f(key)
	}
}
func (n *pitNode) Visit(f pitUpdateFunc) {
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
