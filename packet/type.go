package packet

import (
	"errors"
)

const (
	// common
	NAME uint64 = iota
	NAME_COMPONTENT
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
	SIGNATURE_BITS // FIXME, raw 32 byte signature
)

const (
	ONE uint8 = iota
	ZERO_OR_ONE
	ZERO_OR_MORE
	ONE_OR_MORE
)

const (
	UNKNOWN_NUM_TYPE       = "UNKNOWN_NUM_TYPE"
	EMPTY_PARSE_BUFFER     = "EMPTY_PARSE_BUFFER"
	VALUE_CHILDREN_COEXIST = "VALUE_CHILDREN_COEXIST"
	LEFT_OVER              = "LEFT_OVER"
	WRONG_TYPE             = "WRONG_TYPE"
)

type Node struct {
	Type     uint64
	Count    uint8 // 0 = single, 1 = zero or more, 2 = one or more, 3: zero or one
	Children []Node
}

var (
	InterestFormat = Node{Type: INTEREST, Children: []Node{
		// name
		{Type: NAME, Children: []Node{{Type: NAME_COMPONTENT, Count: ZERO_OR_MORE}}},
		// selectors
		{Type: SELECTORS, Count: ZERO_OR_ONE, Children: []Node{
			{Count: ZERO_OR_ONE, Type: MIN_SUFFIX_COMPONENT},
			{Count: ZERO_OR_ONE, Type: MAX_SUFFIX_COMPONENT},
			{Count: ZERO_OR_ONE, Type: PUBLISHER_PUBLICKEY_LOCATOR, Children: []Node{
				{Type: NAME, Children: []Node{{Type: NAME_COMPONTENT, Count: ZERO_OR_MORE}}},
			}},
			{Count: ZERO_OR_ONE, Type: EXCLUDE, Children: []Node{
				{Count: ZERO_OR_ONE, Type: ANY},
				{Count: ONE_OR_MORE, Type: GROUP_AND, Children: []Node{
					{Type: NAME_COMPONTENT},
					{Count: ZERO_OR_ONE, Type: ANY},
				}},
			}},
			{Count: ZERO_OR_ONE, Type: CHILD_SELECTOR},
			{Count: ZERO_OR_ONE, Type: MUST_BE_FRESH},
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
		{Type: NAME, Children: []Node{{Type: NAME_COMPONTENT, Count: ZERO_OR_MORE}}},
		// meta info
		{Type: META_INFO, Children: []Node{
			{Count: ZERO_OR_ONE, Type: CONTENT_TYPE},
			{Count: ZERO_OR_ONE, Type: FRESHNESS_PERIOD},
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
							{Type: NAME, Children: []Node{{Type: NAME_COMPONTENT, Count: ZERO_OR_MORE}}},
						}},
					}},
					{Type: SIGNATURE_BITS},
				}},
				{Type: SIGNATURE_SHA256_WITH_RSA_AND_MERKLE, Children: []Node{
					{Type: KEY_LOCATOR, Children: []Node{
						{Type: CERTIFICATE_NAME, Children: []Node{
							{Type: NAME, Children: []Node{{Type: NAME_COMPONTENT, Count: ZERO_OR_MORE}}},
						}},
					}},
					{Type: WITNESS},
					{Type: SIGNATURE_BITS},
				}},
			}},
		}},
	}}
)

func NodeMatcher(n Node, raw []byte) (tlv *TLV, remain []byte, err error) {
	tlv = new(TLV)
	switch n.Type {
	case GROUP_OR:
		tlv.Type = GROUP_OR
	case GROUP_AND:
		tlv.Type = GROUP_AND
	case ANY:
		fallthrough
	default:
		remain, err = tlv.Parse(raw)
		if err != nil {
			return
		}
		if n.Type != tlv.Type {
			err = errors.New(WRONG_TYPE)
			return
		}
	}
	if len(n.Children) != 0 {
		// if it is GROUP, dont parse from value of TLV
		var b []byte
		if n.Type == GROUP_AND || n.Type == GROUP_OR {
			b = raw
		} else {
			b = tlv.Value
		}
		tlv.Value = nil
		for i, c := range n.Children {
			count := 0
			for {
				r, rb, err := NodeMatcher(c, b)
				if err != nil {
					break
				}
				// if children is GROUP, append grand children
				if c.Type == GROUP_AND || c.Type == GROUP_OR {
					for _, rr := range r.Children {
						tlv.Children = append(tlv.Children, rr)
					}
				} else {
					tlv.Children = append(tlv.Children, r)
				}

				b = rb
				count++
				// only need 1 match for these types
				if c.Count == ONE || c.Count == ZERO_OR_ONE {
					break
				}
			}
			// if it is failed OR and it is not the last child, try again
			if err != nil && n.Type == GROUP_OR && i < len(n.Children)-1 {
				err = nil
				continue
			}
			switch c.Count {
			case ONE:
				if err != nil {
					return
				}
			case ONE_OR_MORE:
				if err != nil {
					if (err.Error() == WRONG_TYPE || err.Error() == EMPTY_PARSE_BUFFER) && count >= 1 {
						err = nil
						continue
					}
					return
				}
			case ZERO_OR_ONE:
				fallthrough
			case ZERO_OR_MORE:
				if err != nil {
					if err.Error() == WRONG_TYPE || err.Error() == EMPTY_PARSE_BUFFER {
						err = nil
						continue
					}
					return
				}
			}

			// for OR, only the match the first
			if n.Type == GROUP_OR {
				break
			}
		}
		if len(b) != 0 {
			err = errors.New(LEFT_OVER)
			return
		}
	}
	return
}
