package main

import (
	"fmt"
	"github.com/taylorchu/ndn"
)

func main() {
	interest := ndn.Interest{
		Name: "/facebook/users",
	}

	interest.Selectors.MinSuffixComponents = 3
	interest.Selectors.MaxSuffixComponents = 5
	interest.Selectors.ChildSelector = 4
	interest.Selectors.MustBeFresh = true
	interest.Scope = 8
	interest.InterestLifeTime = 9
	interest.Nonce = []byte{0x1, 0x2, 0x3}
	b, err := interest.Encode()
	if err != nil {
		fmt.Println("encode", err)
	}

	interest_decode := ndn.Interest{}
	err = interest_decode.Decode(b)
	if err != nil {
		fmt.Println("decode", err)
	}
	fmt.Printf("%#v\n", interest_decode)

	data := ndn.Data{
		Name: "/google/search",
	}
	data.MetaInfo.ContentType = 2
	data.MetaInfo.FreshnessPeriod = 3
	data.Content = []byte{0x1, 0x2, 0x3}

	data.Signature.Type = 1
	data.Signature.Value = []byte{0x1, 0x2, 0x3}

	b, err = data.Encode()
	if err != nil {
		fmt.Println("encode", err)
	}

	data_decode := ndn.Data{}
	err = data_decode.Decode(b)
	if err != nil {
		fmt.Println("decode", err, b)
	}
	fmt.Printf("%#v\n", data_decode)
}
