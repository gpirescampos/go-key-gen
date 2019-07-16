package main

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func PublicKeyBytesToEthereumAddress(publicKey []byte) string {
	var buf []byte

	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKey[1:]) // remove EC prefix 04
	buf = hash.Sum(nil)
	address := buf[12:]

	return hex.EncodeToString(address)
}

func main() {
	// Generate a mnemonic for memorization or user-friendly seeds
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)

	// Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	seed := bip39.NewSeed(mnemonic, "Secret Passphrase")

	masterKey, _ := bip32.NewMasterKey(seed)
	publicKey := masterKey.PublicKey()

	// Display mnemonic and keys
	fmt.Println("Mnemonic: ", mnemonic)
	fmt.Println("Seed: ", hex.EncodeToString(seed))
	fmt.Println("BIP32 Root Key: ", masterKey)
	fmt.Println("Master public key: ", publicKey)

	publicAddress := PublicKeyBytesToEthereumAddress(publicKey.Key)
	fmt.Println("0x" + publicAddress) // 96216849c49358b10257cb55b28ea603c874b05e
}
