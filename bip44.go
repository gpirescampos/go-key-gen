package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
)

type ChangeType uint32

type AccountKey struct {
	extendedKey *hdkeychain.ExtendedKey
	startPath   HDStartPath
}

func NewAccountKeyFromXPubKey(value string) (*AccountKey, error) {
	xKey, err := hdkeychain.NewKeyFromString(value)

	if err != nil {
		return nil, err
	}

	return &AccountKey{
		extendedKey: xKey,
	}, nil
}

func (k *AccountKey) DeriveP2PKAddress(changeType ChangeType, index uint32, network Network) (*Address, error) {

	if k.extendedKey.IsPrivate() {
		changeType = HardenedKeyZeroIndex + changeType
		index = HardenedKeyZeroIndex + index
	}

	var changeTypeIndex = uint32(changeType)

	changeTypeK, err := k.extendedKey.Child(changeTypeIndex)
	if err != nil {
		return nil, err
	}

	addressK, err := changeTypeK.Child(index)
	if err != nil {
		return nil, err
	}

	netParam, err := networkToChainConfig(network)

	if err != nil {
		return nil, err
	}

	a, err := addressK.Address(netParam)

	if err != nil {
		return nil, err
	}

	address := &Address{
		HDStartPath: HDStartPath{
			PurposeIndex:  k.startPath.PurposeIndex,
			CoinTypeIndex: k.startPath.CoinTypeIndex,
			AccountIndex:  k.startPath.AccountIndex,
		},
		HDEndPath: HDEndPath{
			ChangeIndex:  changeTypeIndex,
			AddressIndex: index,
		},
		Value: a.EncodeAddress(),
	}

	return address, nil
}

const (
	ExternalChangeType ChangeType = 0
	InternalChangeType ChangeType = 1
)

const HardenedKeyZeroIndex = 0x80000000

type Purpose uint32

const (
	BIP44Purpose Purpose = 44
)

type CoinType uint32

const (
	BitcoinCoinType CoinType = 0
	TestnetCoinType CoinType = 1
)

type ExtendedKey struct {
	key *hdkeychain.ExtendedKey
}

type HDStartPath struct {
	PurposeIndex  uint32 `json:"purpose_index"`
	CoinTypeIndex uint32 `json:"coin_type"`
	AccountIndex  uint32 `json:"account_index"`
}

type HDEndPath struct {
	ChangeIndex  uint32 `json:"change_index"`
	AddressIndex uint32 `json:"address_index"`
}

type Address struct {
	HDStartPath HDStartPath `json:"hd_start_path"`
	HDEndPath   HDEndPath   `json:"hd_end_path"`
	Value       string      `json:"value"`
}

type Network int16

const (
	TESTNET3 Network = 0
	MAINNET  Network = 1
)

type Mnemonic struct {
	Value string
}

type URIParams struct {
	Address string
	Amount  float64
	Label   string
	Message string
}

func EncodeURI(p URIParams) (string, error) {

	// TODO check if valid address
	if p.Address == "" {
		return "", fmt.Errorf("invalid address")
	}

	if p.Amount == 0 {
		return "", fmt.Errorf("invalid amount '0'")
	}

	var uri = fmt.Sprintf(
		"bitcoin:%s?amount=%s",
		p.Address,
		strconv.FormatFloat(p.Amount, 'f', -1, 64),
	)

	if p.Label != "" {
		uri = uri + fmt.Sprintf("&label=%s", p.Label)
	}

	if p.Message != "" {
		uri = uri + fmt.Sprintf("&message=%s", p.Message)
	}

	return uri, nil
}

// bitSize must be a multiple of 32
func NewMnemonic(bitSize int) (*Mnemonic, error) {
	entropy, e := NewEntropy(bitSize)

	if e != nil {
		return nil, e
	}

	m, e := NewMnemonicBip39(entropy)

	return &Mnemonic{m}, e
}

func ParseMnemonic(mnemonic string) Mnemonic {
	return Mnemonic{mnemonic}
}

func (m Mnemonic) NewSeed(password string) ([]byte, error) {
	return NewSeedWithErrorChecking(m.Value, password)
}

func networkToChainConfig(net Network) (*chaincfg.Params, error) {
	switch net {
	case TESTNET3:
		return &chaincfg.TestNet3Params, nil

	case MAINNET:
		return &chaincfg.MainNetParams, nil
	}

	return nil, errors.New("invalid network")
}

func NewKeyFromSeedHex(seed string, net Network) (*ExtendedKey, error) {

	pk, err := hex.DecodeString(seed)

	if err != nil {
		return nil, err
	}

	return NewKeyFromSeedBytes(pk, net)
}

func NewKeyFromSeedBytes(seed []byte, net Network) (*ExtendedKey, error) {

	n, err := networkToChainConfig(net)

	if err != nil {
		return nil, err
	}

	xKey, err := hdkeychain.NewMaster(seed, n)

	if err != nil {
		return nil, err
	}

	return &ExtendedKey{
		key: xKey,
	}, nil
}

func (e *ExtendedKey) BIP44AccountKey(coinType CoinType, accIndex uint32, includePrivateKey bool) (*AccountKey, error) {

	return e.baseDeriveAccount(BIP44Purpose, coinType, accIndex, includePrivateKey)
}

func (e *ExtendedKey) baseDeriveAccount(purpose Purpose, coinType CoinType, accIndex uint32, includePrivateKey bool) (*AccountKey, error) {

	var purposeIndex = uint32(purpose)
	var coinTypeIndex = uint32(coinType)

	if e.key.IsPrivate() {
		purposeIndex = HardenedKeyZeroIndex + purposeIndex
		coinTypeIndex = HardenedKeyZeroIndex + coinTypeIndex
		accIndex = HardenedKeyZeroIndex + accIndex
	}

	purposeK, err := e.key.Child(purposeIndex)
	if err != nil {
		return nil, err
	}

	cTypeK, err := purposeK.Child(coinTypeIndex)
	if err != nil {
		return nil, err
	}

	accK, err := cTypeK.Child(accIndex)
	if err != nil {
		return nil, err
	}

	hdStartPath := HDStartPath{
		PurposeIndex:  purposeIndex,
		CoinTypeIndex: coinTypeIndex,
		AccountIndex:  accIndex,
	}

	if includePrivateKey {
		return &AccountKey{
			extendedKey: accK,
			startPath:   hdStartPath,
		}, nil
	}

	pub, err := accK.Neuter()
	if err != nil {
		return nil, err
	}

	return &AccountKey{
		extendedKey: pub,
		startPath:   hdStartPath,
	}, nil
}
