package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"github.com/taylorchu/ndn"
	"os"
)

var (
	identity = flag.String("i", "/testing/key", "identity")
)

func main() {
	flag.Parse()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	ndn.SignKey = ndn.Key{
		Name:       ndn.NewName(*identity),
		PrivateKey: rsaKey,
	}
	// private key
	f, err := os.Create("default.pri")
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
	f, err = os.Create("default.ndncert")
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
	fmt.Println(*identity, "exported")
}
