package main

import (
	"errors"
	"sync"

	"github.com/btcsuite/btcd/btcec"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/tyler-smith/go-bip39"
)

// Wallet is the underlying wallet struct.
type Wallet struct {
	mnemonic      string
	masterKey     *hdkeychain.ExtendedKey
	masterPrivKey *btcec.PrivateKey
	masterPubKey  *btcec.PublicKey
	seed          []byte
	url           accounts.URL
	paths         map[common.Address]accounts.DerivationPath
	accounts      []accounts.Account
	stateLock     sync.RWMutex
}

func NewWallet(seed []byte) (*Wallet, error) {
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	privKey, _ := masterKey.ECPrivKey()
	pubKey, _ := masterKey.ECPubKey()
	return &Wallet{
		masterKey:     masterKey,
		masterPrivKey: privKey,
		masterPubKey:  pubKey,
		seed:          seed,
		accounts:      []accounts.Account{},
		paths:         map[common.Address]accounts.DerivationPath{},
	}, nil
}

// NewFromMnemonic returns a new wallet from a BIP-39 mnemonic.
func NewFromMnemonic(mnemonic string, passphrase string) (*Wallet, error) {
	if mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}

	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is invalid")
	}

	seed, err := NewSeedFromMnemonic(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}

	wallet, err := NewWallet(seed)
	if err != nil {
		return nil, err
	}
	wallet.mnemonic = mnemonic

	return wallet, nil
}

// NewSeedFromMnemonic returns a BIP-39 seed based on a BIP-39 mnemonic.
func NewSeedFromMnemonic(mnemonic string, passphrase string) ([]byte, error) {
	if mnemonic == "" {
		return nil, errors.New("mnemonic is required")
	}

	return bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
}

// NewMnemonic returns a randomly generated BIP-39 mnemonic using 128-256 bits of entropy.
func NewMnemonic(bits int) (string, error) {
	entropy, err := bip39.NewEntropy(bits)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}
