package ndn

import (
	"errors"
	"fmt"
)

/*
	NDN packet encoding with TLV
*/

const (
	GROUP_AND                   uint64 = 1 // only useful for parsing
	GROUP_OR                           = 2 // only useful for parsing
	INTEREST                           = 5
	DATA                               = 6
	NAME                               = 7
	NAME_COMPONENT                     = 8
	SELECTORS                          = 9
	NONCE                              = 10
	SCOPE                              = 11
	INTEREST_LIFETIME                  = 12
	MIN_SUFFIX_COMPONENTS              = 13
	MAX_SUFFIX_COMPONENTS              = 14
	PUBLISHER_PUBLICKEY_LOCATOR        = 15
	EXCLUDE                            = 16
	CHILD_SELECTOR                     = 17
	MUST_BE_FRESH                      = 18
	ANY                                = 19
	META_INFO                          = 20
	CONTENT                            = 21
	SIGNATURE_INFO                     = 22
	SIGNATURE_VALUE                    = 23
	CONTENT_TYPE                       = 24
	FRESHNESS_PERIOD                   = 25
	FINAL_BLOCK_ID                     = 26
	SIGNATURE_TYPE                     = 27
	KEY_LOCATOR                        = 28
	KEY_LOCATOR_DIGEST                 = 29
)

func nodeType(t uint64) string {
	switch t {
	case GROUP_AND:
		return "GROUP_AND"
	case GROUP_OR:
		return "GROUP_OR"
	case INTEREST:
		return "INTEREST"
	case DATA:
		return "DATA"
	case NAME:
		return "NAME"
	case NAME_COMPONENT:
		return "NAME_COMPONENT"
	case SELECTORS:
		return "SELECTORS"
	case NONCE:
		return "NONCE"
	case SCOPE:
		return "SCOPE"
	case INTEREST_LIFETIME:
		return "INTEREST_LIFETIME"
	case MIN_SUFFIX_COMPONENTS:
		return "MIN_SUFFIX_COMPONENTS"
	case MAX_SUFFIX_COMPONENTS:
		return "MAX_SUFFIX_COMPONENTS"
	case PUBLISHER_PUBLICKEY_LOCATOR:
		return "PUBLISHER_PUBLICKEY_LOCATOR"
	case EXCLUDE:
		return "EXCLUDE"
	case CHILD_SELECTOR:
		return "CHILD_SELECTOR"
	case MUST_BE_FRESH:
		return "MUST_BE_FRESH"
	case ANY:
		return "ANY"
	case META_INFO:
		return "META_INFO"
	case CONTENT:
		return "CONTENT"
	case SIGNATURE_INFO:
		return "SIGNATURE_INFO"
	case SIGNATURE_VALUE:
		return "SIGNATURE_VALUE"
	case CONTENT_TYPE:
		return "CONTENT_TYPE"
	case FRESHNESS_PERIOD:
		return "FRESHNESS_PERIOD"
	case FINAL_BLOCK_ID:
		return "FINAL_BLOCK_ID"
	case SIGNATURE_TYPE:
		return "SIGNATURE_TYPE"
	case KEY_LOCATOR:
		return "KEY_LOCATOR"
	case KEY_LOCATOR_DIGEST:
		return "KEY_LOCATOR_DIGEST"
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
			{Type: MIN_SUFFIX_COMPONENTS, Count: ZERO_OR_ONE},
			{Type: MAX_SUFFIX_COMPONENTS, Count: ZERO_OR_ONE},
			{Type: KEY_LOCATOR, Count: ZERO_OR_ONE, Children: []Node{
				{Type: GROUP_OR, Children: []Node{
					{Type: NAME, Children: []Node{{Type: NAME_COMPONENT, Count: ZERO_OR_MORE}}},
					{Type: KEY_LOCATOR_DIGEST},
				}},
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
			{Type: FINAL_BLOCK_ID, Count: ZERO_OR_ONE, Children: []Node{
				{Type: NAME_COMPONENT},
			}},
		}},
		// content
		{Type: CONTENT},
		// signature
		{Type: SIGNATURE_INFO, Children: []Node{
			{Type: SIGNATURE_TYPE},
			{Type: KEY_LOCATOR, Count: ZERO_OR_ONE, Children: []Node{
				{Type: GROUP_OR, Children: []Node{
					{Type: NAME, Children: []Node{{Type: NAME_COMPONENT, Count: ZERO_OR_MORE}}},
					{Type: KEY_LOCATOR_DIGEST},
				}},
			}},
		}},
		{Type: SIGNATURE_VALUE},
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
		err = errors.New(fmt.Sprintf("%s: expected %s, got %s", WRONG_TYPE, nodeType(n.Type), nodeType(tlv.Type)))
		remain = raw
		return
	}
	//fmt.Println(nodeType(tlv.Type))
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
		err = errors.New(fmt.Sprintf("%s: %s", WRONG_TYPE, nodeType(n.Type)))
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
			err = errors.New(fmt.Sprintf("%s: %s %s", WRONG_COUNT, nodeType(n.Type), nodeCount(n.Count)))
			return
		}
	case ONE_OR_MORE:
		if count == 0 {
			err = errors.New(fmt.Sprintf("%s: %s %s", WRONG_COUNT, nodeType(n.Type), nodeCount(n.Count)))
			return
		}
	}
	return
}
