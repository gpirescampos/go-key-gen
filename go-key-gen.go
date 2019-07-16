package main

import (
	"encoding/hex"
	"fmt"
	"log"

	ethhdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/patcito/monero"
	"github.com/patcito/monero/crypto"
	"github.com/stellar/go/keypair"
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

func GenerateStellarWallet(seed []byte) {
	// Generate a new randomly generated address
	var seed32 [32]byte
	copy(seed32[:], seed)
	pair, err := keypair.FromRawSeed(seed32)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Stellar Seed:", pair.Seed())
	fmt.Println("Stellar Address:", pair.Address())
}

func GenerateTronWallet(seed []byte) {
	key := generateNewKey(seed)
	addressFromKey(hex.EncodeToString(key.D.Bytes()))
}

func GenerateMoneroWallet(seed []byte) {
	var seed32 [32]byte
	copy(seed32[:], seed)
	var secret [32]byte
	var view_secret [32]byte
	var spend_secret [32]byte
	crypto.SecretFromSeed(&secret, &seed32)
	account, _ := monero.RecoverAccount(secret)
	spend_secret = account.Secret()
	crypto.ViewFromSpend(&view_secret, &spend_secret)
	fmt.Printf("Monero Address: %s\n", account.Address().String())
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
	GenerateStellarWallet(seed)
	GenerateTronWallet(seed)
	GenerateMoneroWallet(seed)

}
