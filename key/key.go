package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/taylorchu/ndn"
	"os"
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
	f, err := os.Create("testing.pri")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()
	err = ndn.SignKey.EncodePrivateKey(f)
	if err != nil {
		fmt.Println(err)
		return
	}
	// public key
	f, err = os.Create("testing.ndncert")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()
	err = ndn.SignKey.EncodeCertificate(f)
	if err != nil {
		fmt.Println(err)
		return
	}
	// print
	f, err = os.Open("testing.ndncert")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()
	ndn.PrintCertificate(f)
}
