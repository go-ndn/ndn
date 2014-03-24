package packet

import (
	"errors"
)

func ParseDataPacket(raw []byte) (data *TLV, err error) {
	data, remain, err := MatchNode(DataFormat, raw)
	if err != nil {
		return
	}
	if len(remain) != 0 {
		err = errors.New(LEFT_OVER)
	}
	return
}
