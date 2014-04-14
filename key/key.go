package main

import (
	"fmt"
	"github.com/taylorchu/ndn"
	"io/ioutil"
)

func main() {
	var err error
	ndn.SignKey, err = ndn.NewKey("/testing/key")
	fmt.Println(ndn.SignKey.Name)
	if err != nil {
		fmt.Println(err)
		return
	}
	b := ndn.SignKey.Encode()
	ioutil.WriteFile("testing.pri", b, 0777)
	b, err = ndn.SignKey.EncodeCertificate()
	if err != nil {
		fmt.Println(err)
		return
	}
	ndn.PrintCertificate(b)
	ioutil.WriteFile("testing.ndncert", b, 0777)
}
