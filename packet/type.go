package packet

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// common
	NAME uint64 = iota
	NAME_COMPONENT
	GROUP_AND // only useful for parsing
	GROUP_OR  // only useful for parsing
	// interest
	INTEREST
	SELECTORS
	NONCE
	MIN_SUFFIX_COMPONENT
	MAX_SUFFIX_COMPONENT
	PUBLISHER_PUBLICKEY_LOCATOR
	EXCLUDE
	ANY
	CHILD_SELECTOR
	MUST_BE_FRESH
	SCOPE
	INTEREST_LIFETIME
	//data
	DATA
	META_INFO
	CONTENT_TYPE
	FRESHNESS_PERIOD
	CONTENT
	SIGNATURE
	DIGEST_SHA256
	SIGNATURE_SHA256_WITH_RSA
	SIGNATURE_SHA256_WITH_RSA_AND_MERKLE
	KEY_LOCATOR
	CERTIFICATE_NAME
	WITNESS
	SIGNATURE_BITS
)

func nodeType(t uint64) string {
	switch t {
	case NAME:
		return "NAME"
	case NAME_COMPONENT:
		return "NAME_COMPONENT"
	case INTEREST:
		return "INTEREST"
	case SELECTORS:
		return "SELECTORS"
	case NONCE:
		return "NONCE"
	case MIN_SUFFIX_COMPONENT:
		return "MIN_SUFFIX_COMPONENT"
	case MAX_SUFFIX_COMPONENT:
		return "MAX_SUFFIX_COMPONENT"
	case PUBLISHER_PUBLICKEY_LOCATOR:
		return "PUBLISHER_PUBLICKEY_LOCATOR"
	case EXCLUDE:
		return "EXCLUDE"
	case ANY:
		return "ANY"
	case CHILD_SELECTOR:
		return "CHILD_SELECTOR"
	case MUST_BE_FRESH:
		return "MUST_BE_FRESH"
	case SCOPE:
		return "SCOPE"
	case INTEREST_LIFETIME:
		return "INTEREST_LIFETIME"
	case DATA:
		return "DATA"
	case META_INFO:
		return "META_INFO"
	case CONTENT_TYPE:
		return "CONTENT_TYPE"
	case FRESHNESS_PERIOD:
		return "FRESHNESS_PERIOD"
	case CONTENT:
		return "CONTENT"
	case SIGNATURE:
		return "SIGNATURE"
	case DIGEST_SHA256:
		return "DIGEST_SHA256"
	case SIGNATURE_SHA256_WITH_RSA:
		return "SIGNATURE_SHA256_WITH_RSA"
	case SIGNATURE_SHA256_WITH_RSA_AND_MERKLE:
		return "SIGNATURE_SHA256_WITH_RSA_AND_MERKLE"
	case KEY_LOCATOR:
		return "KEY_LOCATOR"
	case CERTIFICATE_NAME:
		return "CERTIFICATE_NAME"
	case WITNESS:
		return "WITNESS"
	case SIGNATURE_BITS:
		return "SIGNATURE_BITS"
	}
	return "UNKNOWN"
}

func nodeCount(c uint8) string {
	switch c {
	case ONE:
		return "ONE"
	case ZERO_OR_MORE:
		return "ZERO_OR_MORE"
	case ZERO_OR_ONE:
		return "ZERO_OR_ONE"
	case ONE_OR_MORE:
		return "ONE_OR_MORE"
	}
	return "UNKNOWN"
}

const (
	ONE uint8 = iota
	ZERO_OR_ONE
	ZERO_OR_MORE
	ONE_OR_MORE
)

type Node struct {
	Type     uint64
	Count    uint8 // 0 = single, 1 = zero or more, 2 = one or more, 3: zero or one
	Children []Node
}

func (this Node) String() string {
	return fmt.Sprintf("[%s(%d), Count: %s]", nodeType(this.Type), this.Type, nodeCount(this.Count))
}

var (
	InterestFormat = Node{Type: INTEREST, Children: []Node{
		// name
		{Type: NAME, Children: []Node{{Type: NAME_COMPONENT, Count: ZERO_OR_MORE}}},
		// selectors
		{Type: SELECTORS, Count: ZERO_OR_ONE, Children: []Node{
			{Type: MIN_SUFFIX_COMPONENT, Count: ZERO_OR_ONE},
			{Type: MAX_SUFFIX_COMPONENT, Count: ZERO_OR_ONE},
			{Type: PUBLISHER_PUBLICKEY_LOCATOR, Count: ZERO_OR_ONE, Children: []Node{
				{Type: NAME, Children: []Node{{Type: NAME_COMPONENT, Count: ZERO_OR_MORE}}},
			}},
			{Type: EXCLUDE, Count: ZERO_OR_ONE, Children: []Node{
				{Type: ANY, Count: ZERO_OR_ONE},
				{Type: GROUP_AND, Count: ONE_OR_MORE, Children: []Node{
					{Type: NAME_COMPONENT},
					{Type: ANY, Count: ZERO_OR_ONE},
				}},
			}},
			{Type: CHILD_SELECTOR, Count: ZERO_OR_ONE},
			{Type: MUST_BE_FRESH, Count: ZERO_OR_ONE},
		}},
		// nonce
		{Type: NONCE},
		// scope
		{Type: SCOPE, Count: ZERO_OR_ONE},
		// scope
		{Type: INTEREST_LIFETIME, Count: ZERO_OR_ONE},
	}}

	DataFormat = Node{Type: DATA, Children: []Node{
		// name
		{Type: NAME, Children: []Node{{Type: NAME_COMPONENT, Count: ZERO_OR_MORE}}},
		// meta info
		{Type: META_INFO, Children: []Node{
			{Type: CONTENT_TYPE, Count: ZERO_OR_ONE},
			{Type: FRESHNESS_PERIOD, Count: ZERO_OR_ONE},
		}},
		// content
		{Type: CONTENT},
		// signature
		{Type: SIGNATURE, Children: []Node{
			{Type: GROUP_OR, Children: []Node{
				{Type: DIGEST_SHA256},
				{Type: SIGNATURE_SHA256_WITH_RSA, Children: []Node{
					{Type: KEY_LOCATOR, Children: []Node{
						{Type: CERTIFICATE_NAME, Children: []Node{
							{Type: NAME, Children: []Node{{Type: NAME_COMPONENT, Count: ZERO_OR_MORE}}},
						}},
					}},
					{Type: SIGNATURE_BITS},
				}},
				{Type: SIGNATURE_SHA256_WITH_RSA_AND_MERKLE, Children: []Node{
					{Type: KEY_LOCATOR, Children: []Node{
						{Type: CERTIFICATE_NAME, Children: []Node{
							{Type: NAME, Children: []Node{{Type: NAME_COMPONENT, Count: ZERO_OR_MORE}}},
						}},
					}},
					{Type: WITNESS},
					{Type: SIGNATURE_BITS},
				}},
			}},
		}},
	}}
)

func DecodeData(raw []byte) (data *TLV, err error) {
	data, remain, err := matchNode(DataFormat, raw)
	if err != nil {
		return
	}
	if len(remain) != 0 {
		err = errors.New(BUFFER_NOT_EMPTY)
	}
	return
}

func DecodeInterest(raw []byte) (interest *TLV, err error) {
	interest, remain, err := matchNode(InterestFormat, raw)
	if err != nil {
		return
	}
	if len(remain) != 0 {
		err = errors.New(BUFFER_NOT_EMPTY)
	}
	return
}

// prefix match one node
func matchNode(n Node, raw []byte) (tlv *TLV, remain []byte, err error) {
	//fmt.Printf("%v %v\n", n, raw)
	tlv = new(TLV)
	remain, err = tlv.Decode(raw)
	if err != nil {
		return
	}
	// type does not match; don't touch remain
	if n.Type != tlv.Type {
		err = errors.New(WRONG_TYPE)
		remain = raw
		return
	}
	// turn tlv.value into children
	if len(n.Children) != 0 {
		b := tlv.Value
		// value and children are mutual exclusive
		tlv.Value = nil

		for _, c := range n.Children {
			var matched []*TLV
			matched, b, err = matchChildNode(c, b)
			if err != nil {
				return
			}
			for _, m := range matched {
				tlv.Add(m)
			}
		}
		if len(b) != 0 {
			err = errors.New(BUFFER_NOT_EMPTY)
			return
		}
	}
	return
}

// prefix match and-node once; ignore count
func matchGroupAndNode(n Node, raw []byte) (matched []*TLV, remain []byte, err error) {
	remain = raw
	for _, c := range n.Children {
		var m []*TLV
		m, remain, err = matchChildNode(c, remain)
		if err != nil {
			// and: one fails and all fail
			return
		}
		matched = append(matched, m...)
	}
	return
}

// prefix match or-node once; ignore count
func matchGroupOrNode(n Node, raw []byte) (matched []*TLV, remain []byte, err error) {
	remain = raw
	for _, c := range n.Children {
		var m []*TLV
		m, remain, err = matchChildNode(c, remain)
		if err != nil {
			// or: ignore error and try another
			err = nil
			continue
		} else {
			matched = append(matched, m...)
			break
		}
	}
	// OR should at least have one match;
	if len(matched) == 0 {
		err = errors.New(WRONG_TYPE)
		return
	}
	return
}

// perform match once for and/or/other type; handle count
func matchChildNode(n Node, raw []byte) (matched []*TLV, remain []byte, err error) {
	remain = raw
	count := 0
	for {
		var mm []*TLV
		switch n.Type {
		case GROUP_AND:
			mm, remain, err = matchGroupAndNode(n, remain)
		case GROUP_OR:
			mm, remain, err = matchGroupOrNode(n, remain)
		default:
			var m *TLV
			m, remain, err = matchNode(n, remain)
			if err == nil {
				mm = append(mm, m)
			}
		}
		if err != nil {
			err = nil
			break
		}
		matched = append(matched, mm...)
		count++
		// if only need one, don't get greedy
		if n.Count == ONE || n.Count == ZERO_OR_ONE {
			break
		}
	}
	// check for not enough count
	switch n.Count {
	case ONE:
		if count != 1 {
			err = errors.New(WRONG_COUNT)
			return
		}
	case ONE_OR_MORE:
		if count == 0 {
			err = errors.New(WRONG_COUNT)
			return
		}
	}
	return
}

// /example/prefix
func Name(s string) (tlv *TLV) {
	tlv = new(TLV)
	tlv.Type = NAME
	for _, comp := range strings.Split(s, "/") {
		c := new(TLV)
		c.Type = NAME_COMPONENT
		c.Value = []byte(comp)
		tlv.Add(c)
	}
	return
}

// tlv type = name
func Uri(tlv *TLV) string {
	comp := []string{}
	for _, c := range tlv.Children {
		comp = append(comp, string(c.Value))
	}
	return strings.Join(comp, "/")
}
