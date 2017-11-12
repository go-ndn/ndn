package ndn

import "container/list"

//go:generate gorewrite

func init() {
	cacheNodeValEmpty = func(t map[string]*list.Element) bool {
		return t == nil
	}
	pitNodeValEmpty = func(t map[chan<- *Data]pitEntry) bool {
		return t == nil
	}
}
