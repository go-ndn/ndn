package ndn

import "container/list"

//go:generate generic github.com/go-ndn/lpm/matcher .pit Type->map[chan<-*Data]pitEntry TypeMatcher->pitMatcher
//go:generate generic github.com/go-ndn/lpm/matcher .cache Type->container/list:map[string]*list.Element TypeMatcher->cacheMatcher

func init() {
	cacheNodeValEmpty = func(t map[string]*list.Element) bool {
		return t == nil
	}
	pitNodeValEmpty = func(t map[chan<- *Data]pitEntry) bool {
		return t == nil
	}
}
