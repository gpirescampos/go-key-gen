package main

import (
	"encoding/hex"
	"fmt"
)

// Example address creation for a fictitious company ComputerVoice Inc. where
// each department has their own wallet to manage
func main() {

	bitSize := 256
	mnemonic, _ := NewMnemonic(bitSize)
	seedBytes, err := mnemonic.NewSeed("my password")
	if err != nil {
		return
	}
	// // Generate a mnemonic for memorization or user-friendly seeds
	// // entropy, _ := NewEntropy(256)
	// // mnemonic, _ := NewMnemonic(entropy)

	// // Generate a Bip32 HD wallet for the mnemonic and a user supplied password
	// seed, err := NewSeedWithErrorChecking(MNEMOIC, PASSPHRASE)
	// if err != nil {
	// 	return
	// }

	// masterKey, _ := NewMasterKey(seed)
	// // publicKey := masterKey.PublicKey()

	// Display mnemonic and keys
	fmt.Println("Seed: ", hex.EncodeToString(seedBytes))
	fmt.Println("Mnemonic: ", mnemonic)
	// fmt.Println("BIP32 Master Key: ", masterKey)
	// fmt.Println("Master public key: ", publicKey)
}
