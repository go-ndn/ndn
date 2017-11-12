package ndn

import "github.com/go-ndn/lpm"

type pitMatcher struct{ pitNode }

var pitNodeValEmpty func(map[chan<- *Data]pitEntry) bool

type pitNode struct {
	val   map[chan<- *Data]pitEntry
	table map[string]pitNode
}

func (n *pitNode) empty() bool {
	return pitNodeValEmpty(n.val) && len(n.table) == 0
}
func (n *pitNode) update(key []lpm.Component, depth int, f func([]lpm.Component, map[chan<- *Data]pitEntry) map[chan<- *Data]pitEntry, exist, all bool) {
	try := func() {
		if !exist || !pitNodeValEmpty(n.val) {
			n.val = f(key[:depth], n.val)
		}
	}
	if len(key) == depth {
		try()
		return
	}
	if n.table == nil {
		if exist {
			try()
			return
		}
		n.table = make(map[string]pitNode)
	}
	v, ok := n.table[string(key[depth])]
	if !ok {
		if exist {
			try()
			return
		}
	}
	if all {
		try()
	}
	v.update(key, depth+1, f, exist, all)
	if v.empty() {
		delete(n.table, string(key[depth]))
	} else {
		n.table[string(key[depth])] = v
	}
}
func (n *pitNode) match(key []lpm.Component, depth int, f func(map[chan<- *Data]pitEntry), exist bool) {
	try := func() {
		if !exist || !pitNodeValEmpty(n.val) {
			f(n.val)
		}
	}
	if len(key) == depth {
		try()
		return
	}
	if n.table == nil {
		if exist {
			try()
		}
		return
	}
	v, ok := n.table[string(key[depth])]
	if !ok {
		if exist {
			try()
		}
		return
	}
	v.match(key, depth+1, f, exist)
}
func (n *pitNode) visit(key []lpm.Component, f func([]lpm.Component, map[chan<- *Data]pitEntry) map[chan<- *Data]pitEntry) {
	if !pitNodeValEmpty(n.val) {
		n.val = f(key, n.val)
	}
	for k, v := range n.table {
		v.visit(append(key, lpm.Component(k)), f)
		if v.empty() {
			delete(n.table, k)
		} else {
			n.table[k] = v
		}
	}
}
func (n *pitNode) Update(key []lpm.Component, f func(map[chan<- *Data]pitEntry) map[chan<- *Data]pitEntry, exist bool) {
	n.update(key, 0, func(_ []lpm.Component, v map[chan<- *Data]pitEntry) map[chan<- *Data]pitEntry {
		return f(v)
	}, exist, false)
}
func (n *pitNode) UpdateAll(key []lpm.Component, f func([]lpm.Component, map[chan<- *Data]pitEntry) map[chan<- *Data]pitEntry, exist bool) {
	n.update(key, 0, f, exist, true)
}
func (n *pitNode) Match(key []lpm.Component, f func(map[chan<- *Data]pitEntry), exist bool) {
	n.match(key, 0, f, exist)
}
func (n *pitNode) Visit(f func([]lpm.Component, map[chan<- *Data]pitEntry) map[chan<- *Data]pitEntry) {
	key := make([]lpm.Component, 0, 16)
	n.visit(key, f)
}
