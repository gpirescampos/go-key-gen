package main

import (
	"fmt"

	"github.com/eoscanada/eos-go/ecc"
)

func NewKeyPair() {
	priKey, _ := ecc.NewRandomPrivateKey()
	pubKey := priKey.PublicKey()
	fmt.Println("EOS Public  Key: ", priKey, pubKey)
}
