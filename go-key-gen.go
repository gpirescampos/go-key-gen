package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
)

func GenerateEthereumWallet(menmoninc string, seed string) {
	wallet, _ := NewFromMnemonic(menmoninc, seed)
	path := hdwallet.MustParseDerivationPath("m/44'/60'/0'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Master root key: ", wallet.masterKey)
	fmt.Println("Private Extended Key?:", wallet.masterKey.IsPrivate())
	fmt.Println("Master private key: ", wallet.masterPrivKey)
	fmt.Println("Master public key: ", wallet.masterPubKey)
	fmt.Println("Ethereum Address: ", account.Address.Hex())
}

func GenerateBitcoinWallet(seed []byte) {
	// Generate a new master node using the seed.
	key, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Println(err)
		return
	}

	address, _ := key.Address(&chaincfg.MainNetParams)
	// Show that the generated master node extended key is private.
	fmt.Println("Bitcoin Address: ", address)
}

func main() {
	mnemonic, _ := NewMnemonic(256)
	seed, _ := NewSeedFromMnemonic(mnemonic, "pass")

	GenerateEthereumWallet(mnemonic, hex.EncodeToString(seed))
	GenerateBitcoinWallet(seed)

	fmt.Println("Menmonic: ", mnemonic)
	fmt.Println("Seed: ", hex.EncodeToString(seed))
}
