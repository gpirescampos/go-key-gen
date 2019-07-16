package main

import (
	"encoding/hex"
	"fmt"
)

func GenerateBitcoinAddress() {

}

func main() {
	mnemonic, _ := NewMnemonic(256)
	wallet, _ := NewFromMnemonic(mnemonic, "pass")

	fmt.Println("Menmonic: ", mnemonic)
	fmt.Println("Seed: ", hex.EncodeToString(wallet.seed))
	fmt.Println("Master root key: ", wallet.masterKey)
	fmt.Println("Master private key: ", wallet.masterPrivKey)
	fmt.Println("Master public key: ", wallet.masterPubKey)
}
