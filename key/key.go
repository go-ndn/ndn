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
	fmt.Println("name", ndn.SignKey.Name)
	if err != nil {
		fmt.Println(err)
		return
	}
	// private key
	b, err := ndn.SignKey.Encode()
	if err != nil {
		fmt.Println(err)
		return
	}
	ioutil.WriteFile("testing.pri", b, 0777)
	// public key	
	b, err = ndn.SignKey.EncodeCertificate()
	if err != nil {
		fmt.Println(err)
		return
	}
	ioutil.WriteFile("testing.ndncert", b, 0777)
	err = ndn.PrintCertificate(b)
	if err != nil {
		fmt.Println(err)
		return
	}
}
