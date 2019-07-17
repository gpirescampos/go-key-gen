package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/FiloSottile/zcash-mini/zcash"
	"github.com/isarq/nem-sdk-go/model"
	ethhdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/patcito/monero/crypto"
	"github.com/stellar/go/keypair"
	bithdwallet "github.com/wemeetagain/go-hdwallet"
)

func GenerateEthereumWallet(seed []byte) {
	wallet, _ := NewFromMnemonic(seed)
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
	// fmt.Println("Stellar Seed:", pair.Seed())
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
	SecretFromSeed(&secret, &seed32)
	account, _ := RecoverAccount(secret)
	spend_secret = account.Secret()
	crypto.ViewFromSpend(&view_secret, &spend_secret)
	fmt.Println("Monero Address: ", account.Address().String())
}

func GenerateIotaWallet() {
	iotaSeed, _ := generateRandomSeed()
	fmt.Println("IOTA Seed: ", iotaSeed)
}

func GenerateNeoWallet(seed []byte) {
	privKey, _ := NewPrivateKeyFromWIF(seed)
	address, _ := privKey.PublicAddress()
	fmt.Println("Neo Address: ", address)
}

func GenerateTezosWallet(seed []byte) {
	wallet, _ := CreateWallet(seed)
	fmt.Println("Tezos Address: ", wallet.Address)
}

func GenerateZCashWallet(seed []byte) {

	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		panic(err)
	}
	rawKey[0] &= 0x0f

	rawAddr, err := zcash.KeyToAddress(rawKey)
	if err != nil {
		fatal(err)
	}
	addr := zcash.Base58Encode(rawAddr, zcash.ProdAddress)
	fmt.Println("ZCash Shielded Address: ", addr)
}

func GenerateLiskWallet(seed []byte) {
	prvKey := GetPrivateKeyFromSecret(hex.EncodeToString(seed))
	pubKey := GetPublicKeyFromSecret(hex.EncodeToString(prvKey))
	addr := GetAddressFromPublicKey(pubKey)
	fmt.Println("Lisk Address: ", addr)
}

func GenerateNEMWallet(seed []byte) {
	keyPair, _ := model.FromSeed(seed)

	publicKey := keyPair.PublicString()

	address := model.ToAddress(publicKey, model.Data.Mainnet.ID)
	fmt.Println("NEM Address: ", address)
}

func main() {
	passphrase := "pass"
	mnemonic, _ := NewMnemonic(256)
	seed, _ := NewSeedFromMnemonic(mnemonic, passphrase)

	fmt.Println("Menmonic: ", mnemonic)
	fmt.Println("Passphrase: ", passphrase)
	fmt.Println("Seed: ", hex.EncodeToString(seed))

	GenerateEthereumWallet(seed)
	GenerateBitcoinWallet(seed)
	GenerateStellarWallet(seed)
	GenerateTronWallet(seed)
	GenerateMoneroWallet(seed)
	// GenerateIotaWallet()
	GenerateNeoWallet(seed)
	GenerateTezosWallet(seed)
	GenerateZCashWallet(seed)
	GenerateLiskWallet(seed)
	GenerateNEMWallet(seed)
}
