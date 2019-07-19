package gokeygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/sasaxie/go-client-api/common/base58"
	"golang.org/x/crypto/sha3"
)

func generateNewKey(seed []byte) *ecdsa.PrivateKey {
	// Generate a new key using the ECDSA library
	// #1
	var priv *ecdsa.PrivateKey
	seedString := hex.EncodeToString(seed)
	if seedString != "" {
		k := new(big.Int)
		k.SetString(seedString, 16)

		priv = new(ecdsa.PrivateKey)
		curve := elliptic.P256()
		priv.PublicKey.Curve = curve
		priv.D = k
		priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(k.Bytes())
	} else {
		priv, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}

	return priv
}

func addressFromKey(keyStr string) {

	// Build the Private Key and extract the Public Key
	keyBytes, _ := hex.DecodeString(keyStr)
	key := new(ecdsa.PrivateKey)
	key.PublicKey.Curve = btcec.S256()
	key.D = new(big.Int).SetBytes(keyBytes)
	key.PublicKey.X, key.PublicKey.Y = key.PublicKey.Curve.ScalarBaseMult(keyBytes)

	// #1
	pub := append(key.X.Bytes(), key.Y.Bytes()...)

	// #2
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pub)
	hashed := hash.Sum(nil)
	last20 := hashed[len(hashed)-20:]

	// #3
	addr41 := append([]byte{0x41}, last20...)

	// #4
	hash2561 := sha256.Sum256(addr41)
	hash2562 := sha256.Sum256(hash2561[:])
	checksum := hash2562[:4]

	// #5/#6
	rawAddr := append(addr41, checksum...)
	tronAddr := base58.Encode(rawAddr)

	fmt.Println("Tron Address: ", tronAddr)
}
