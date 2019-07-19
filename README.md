# Blockchain wallet generator

## Purpose

This package generates multiple key pairs and addresses for different blockchain wallets, from the same seed.

List of wallet:
 * Bitcoin
 * Ethereum
 * EOS
 * IOTA
 * Lisk
 * Monero
 * NEO
 * Tezos
 * TRON
 * ZCash

## Disclamer

 * **Please not that this code is not production ready, and exists for testing purposes only.**
 * **Code base:** The code is based from existing Go libraries found around Github. In some cases, I recreated the code in this package, so that I could further explore how to use it, and how it work - also because in some cases I had to modify it so that it could accept the seed being generated.
 * **Validity:** All of the addresses generated have been cross-verified against online tools.
 * **EOS:** since accounts need to be registered, the code implemented here stops at the public key generation. An extra step needs to be made to create an account on the [EOS platform](https://www.eosx.io/guides/how-to-create-account)
 * **IOTA:** addresses for IOTA are generated on the fly whenever a new transaction is performed, from a base seed - this code only generates that seed value. This seed is also not being generated from the same base input as the other wallets that exist in this package
 * **ZCash:** Currently I'm only generating a [shielded ZCash address](https://www.mycryptopedia.com/zcash-shielded-transparent-addresses-explained/). Further wotk needs to be done to generate the transparent address associated to the keys

## Usage

Please use to following snippet to use this package:

```
package main

import (
	"encoding/hex"
	"fmt"

	gokeygen "github.com/gpirescampos/go-key-gen"
)

func main() {
	passphrase := INSERT_PASSPHRASE_HERE
	mnemonic, _ := gokeygen.NewMnemonic(256)
	seed, _ := gokeygen.NewSeedFromMnemonic(mnemonic, passphrase)

	fmt.Println("Menmonic: ", mnemonic)
	fmt.Println("Passphrase: ", passphrase)
	fmt.Println("Seed: ", hex.EncodeToString(seed))

	gokeygen.GenerateEthereumWallet(seed)
	gokeygen.GenerateBitcoinWallet(seed)
	gokeygen.GenerateStellarWallet(seed)
	gokeygen.GenerateTronWallet(seed)
	gokeygen.GenerateMoneroWallet(seed)
	// GenerateIotaWallet()
	gokeygen.GenerateNeoWallet(seed)
	gokeygen.GenerateTezosWallet(seed)
	gokeygen.GenerateZCashWallet(seed)
	gokeygen.GenerateLiskWallet(seed)
	gokeygen.GenerateNEMWallet(seed)
	gokeygen.GenerateEOSWallet(seed)
}
```