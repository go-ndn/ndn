package main

import (
	"fmt"
	"github.com/taylorchu/ndn"
)

func main() {
	interest := ndn.Interest("/facebook/users")

	b, _ := interest.Encode()
	fmt.Printf("%v\n", b)

	interest_decode, _ := ndn.DecodeInterest(b)
	fmt.Println(interest_decode.Uri())
}
