package packet

import (
	"errors"
)

func ParseInterestPacket(raw []byte) (interest *TLV, err error) {
	interest, remain, err := MatchNode(InterestFormat, raw)
	if err != nil {
		return
	}
	if len(remain) != 0 {
		err = errors.New(LEFT_OVER)
	}
	return
}
