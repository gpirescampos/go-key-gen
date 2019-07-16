package main

import (
	"encoding/hex"
	"fmt"
	"log"

	ethhdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	bithdwallet "github.com/wemeetagain/go-hdwallet"
)

func GenerateEthereumWallet(menmoninc string, seed string) {
	wallet, _ := NewFromMnemonic(menmoninc, seed)
	path := ethhdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Ethereum Address: ", account.Address.Hex())
}

func GenerateBitcoinWallet(seed []byte) {
	masterprv := bithdwallet.MasterKey(seed)

	address := masterprv.Address()
	fmt.Println("Bitcoin Address: ", address)
}

func main() {
	passphrase := "pass"
	mnemonic, _ := NewMnemonic(256)
	seed, _ := NewSeedFromMnemonic(mnemonic, passphrase)

	fmt.Println("Menmonic: ", mnemonic)
	fmt.Println("Passphrase: ", passphrase)
	fmt.Println("Seed: ", hex.EncodeToString(seed))

	GenerateEthereumWallet(mnemonic, hex.EncodeToString(seed))
	GenerateBitcoinWallet(seed)

}
