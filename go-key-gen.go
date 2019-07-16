package main

import (
	"encoding/hex"
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

func GenerateBitcoinHDWAllet() {

}

func main() {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	seed := bip39.NewSeed(mnemonic, "pass")

	fmt.Println("Entropy: ", hex.EncodeToString(entropy))
	fmt.Println("Menmonic: ", mnemonic)
	fmt.Println("Seed: ", hex.EncodeToString(seed))
}
