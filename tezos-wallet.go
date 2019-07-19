package gokeygen

import (
	"github.com/Messer4/base58check"
	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

var (
	// maxBatchSize tells how many Transactions per batch are allowed.
	maxBatchSize = 200

	// For (de)constructing addresses
	tz1   = []byte{6, 161, 159}
	edsk  = []byte{43, 246, 78, 7}
	edsk2 = []byte{13, 15, 58, 7}
	edpk  = []byte{13, 15, 37, 217}
	edesk = []byte{7, 90, 60, 179, 41}
)

//Wallet needed for signing operations
type TezosWallet struct {
	Address string
	Seed    []byte
	Kp      keyPair
	Sk      string
	Pk      string
}

// Key Pair Storage
type keyPair struct {
	PrivKey []byte
	PubKey  []byte
}

func generatePublicHash(publicKey []byte) (string, error) {
	hash, err := blake2b.New(20, []byte{})
	hash.Write(publicKey)
	if err != nil {
		return "", errors.Wrapf(err, "could not generate public hash from public key %s", string(publicKey))
	}
	return b58cencode(hash.Sum(nil), tz1), nil
}

// CreateWallet returns Wallet with the mnemonic and password provided
func CreateWallet(seed []byte) (TezosWallet, error) {

	var seed32 = seed[0:32]
	privKey := ed25519.NewKeyFromSeed(seed32)
	pubKey := privKey.Public().(ed25519.PublicKey)
	pubKeyBytes := []byte(pubKey)
	signKp := keyPair{PrivKey: privKey, PubKey: pubKeyBytes}

	address, err := generatePublicHash(pubKeyBytes)
	if err != nil {
		return TezosWallet{}, errors.Wrapf(err, "could not create wallet")
	}

	wallet := TezosWallet{
		Address: address,
		Kp:      signKp,
		Seed:    seed,
		Sk:      b58cencode(privKey, edsk),
		Pk:      b58cencode(pubKeyBytes, edpk),
	}

	return wallet, nil
}

//Helper Function to get the right format for wallet.
func b58cencode(payload []byte, prefix []byte) string {
	n := make([]byte, (len(prefix) + len(payload)))
	for k := range prefix {
		n[k] = prefix[k]
	}
	for l := range payload {
		n[l+len(prefix)] = payload[l]
	}
	b58c := base58check.Encode(n)
	return b58c
}
