package ndn

import (
	"container/list"
	"github.com/go-ndn/lpm"
)

type cacheMatcher struct {
	cacheNode
}

var cacheNodeValEmpty func(map[string]*list.Element) bool

type cacheNode struct {
	val   map[string]*list.Element
	table map[string]cacheNode
}

func (n *cacheNode) empty() bool {
	return cacheNodeValEmpty(n.val) && len(n.table) == 0
}

func (n *cacheNode) update(key []lpm.Component, depth int, f func([]lpm.Component, map[string]*list.Element) map[string]*list.Element, exist, all bool) {
	try := func() {
		if depth == 0 {
			return
		}
		if !exist || !cacheNodeValEmpty(n.val) {
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
		n.table = make(map[string]cacheNode)
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

func (n *cacheNode) match(key []lpm.Component, depth int, f func(map[string]*list.Element), exist bool) {
	try := func() {
		if depth == 0 {
			return
		}
		if !exist || !cacheNodeValEmpty(n.val) {
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

func (n *cacheNode) visit(key []lpm.Component, f func([]lpm.Component, map[string]*list.Element) map[string]*list.Element) {
	if !cacheNodeValEmpty(n.val) {
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

func (n *cacheNode) Update(key []lpm.Component, f func(map[string]*list.Element) map[string]*list.Element, exist bool) {
	n.update(key, 0, func(_ []lpm.Component, v map[string]*list.Element) map[string]*list.Element {
		return f(v)
	}, exist, false)
}

func (n *cacheNode) UpdateAll(key []lpm.Component, f func([]lpm.Component, map[string]*list.Element) map[string]*list.Element, exist bool) {
	n.update(key, 0, f, exist, true)
}

func (n *cacheNode) Match(key []lpm.Component, f func(map[string]*list.Element), exist bool) {
	n.match(key, 0, f, exist)
}

func (n *cacheNode) Visit(f func([]lpm.Component, map[string]*list.Element) map[string]*list.Element) {
	key := make([]lpm.Component, 0, 16)
	n.visit(key, f)
}
