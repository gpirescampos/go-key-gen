package main

import (
	"encoding/hex"
	"errors"
	"math/big"
)

const (
	// FirstHardenedChild is the index of the firxt "harded" child key as per the
	// bip32 spec
	FirstHardenedChild = uint32(0x80000000)

	// PublicKeyCompressedLength is the byte count of a compressed public key
	PublicKeyCompressedLength = 33

	PASSPHRASE = "passphrase"

	MNEMOIC = "broom metal merge brown spy shop electric strike damage right pattern talk gain butter museum win run shove bridge explain receive dash thank sweet"
)

var (
	// Some bitwise operands for working with big.Ints
	last11BitsMask  = big.NewInt(2047)
	shift11BitsMask = big.NewInt(2048)
	bigOne          = big.NewInt(1)
	bigTwo          = big.NewInt(2)

	// used to isolate the checksum bits from the entropy+checksum byte array
	wordLengthChecksumMasksMapping = map[int]*big.Int{
		12: big.NewInt(15),
		15: big.NewInt(31),
		18: big.NewInt(63),
		21: big.NewInt(127),
		24: big.NewInt(255),
	}
	// used to use only the desired x of 8 available checksum bits.
	// 256 bit (word length 24) requires all 8 bits of the checksum,
	// and thus no shifting is needed for it (we would get a divByZero crash if we did)
	wordLengthChecksumShiftMapping = map[int]*big.Int{
		12: big.NewInt(16),
		15: big.NewInt(8),
		18: big.NewInt(4),
		21: big.NewInt(2),
	}

	// wordList is the set of words to use
	wordList []string

	// wordMap is a reverse lookup map for wordList
	wordMap map[string]int

	// ErrInvalidMnemonic is returned when trying to use a malformed mnemonic.
	ErrInvalidMnemonic = errors.New("Invalid mnenomic")

	// ErrEntropyLengthInvalid is returned when trying to use an entropy set with
	// an invalid size.
	ErrEntropyLengthInvalid = errors.New("Entropy length must be [128, 256] and a multiple of 32")

	// ErrValidatedSeedLengthMismatch is returned when a validated seed is not the
	// same size as the given seed. This should never happen is present only as a
	// sanity assertion.
	ErrValidatedSeedLengthMismatch = errors.New("Seed length does not match validated seed length")

	// ErrChecksumIncorrect is returned when entropy has the incorrect checksum.
	ErrChecksumIncorrect = errors.New("Checksum incorrect")

	// PrivateWalletVersion is the version flag for serialized private keys
	PrivateWalletVersion, _ = hex.DecodeString("0488ADE4")

	// PublicWalletVersion is the version flag for serialized private keys
	PublicWalletVersion, _ = hex.DecodeString("0488B21E")

	// ErrSerializedKeyWrongSize is returned when trying to deserialize a key that
	// has an incorrect length
	ErrSerializedKeyWrongSize = errors.New("Serialized keys should by exactly 82 bytes")

	// ErrHardnedChildPublicKey is returned when trying to create a harded child
	// of the public key
	ErrHardnedChildPublicKey = errors.New("Can't create hardened child for public key")

	// ErrInvalidChecksum is returned when deserializing a key with an incorrect
	// checksum
	ErrInvalidChecksum = errors.New("Checksum doesn't match")

	// ErrInvalidPrivateKey is returned when a derived private key is invalid
	ErrInvalidPrivateKey = errors.New("Invalid private key")

	// ErrInvalidPublicKey is returned when a derived public key is invalid
	ErrInvalidPublicKey = errors.New("Invalid public key")
)
