package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/taylorchu/ndn"
	"io/ioutil"
)

func main() {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	ndn.SignKey, err = ndn.NewKey("/testing/key", rsaKey)
	fmt.Println(ndn.SignKey.Name)
	if err != nil {
		fmt.Println(err)
		return
	}
	b, err := ndn.SignKey.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}
	ioutil.WriteFile("testing.pri", b, 0777)
	b, err = ndn.SignKey.EncodeCertificate()
	if err != nil {
		fmt.Println(err)
		return
	}
	ndn.PrintCertificate(b)
	ioutil.WriteFile("testing.ndncert", b, 0777)
}
