package gokeygen

import (
	"bytes"
	"crypto/sha256"
	"math/big"

	"golang.org/x/crypto/ed25519"
)

// GetSHA256Hash returns the SHA256 hash of a string as byte slice
func GetSHA256Hash(stringToHash string) [sha256.Size]byte {
	return sha256.Sum256([]byte(stringToHash))
}

// GetBigNumberStringFromBytes returns the BigNumber representation of the bytes as string
func GetBigNumberStringFromBytes(data []byte) string {
	numericAddress := new(big.Int)
	numericAddress.SetBytes(data)

	return numericAddress.Text(10)
}

// GetFirstEightBytesReversed returns the first 8 bytes of a byte slice in reversed order.
func GetFirstEightBytesReversed(bytes []byte) []byte {
	if len(bytes) < 8 {
		return nil
	}

	result := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		result[7-i] = bytes[i]
	}

	return result
}

// GetPrivateKeyFromSecret takes a Lisk secret and returns the associated private key
func GetPrivateKeyFromSecret(secret string) []byte {
	secretHash := GetSHA256Hash(secret)
	_, prKey, _ := ed25519.GenerateKey(bytes.NewReader(secretHash[:sha256.Size]))

	return prKey
}

// GetPublicKeyFromSecret takes a Lisk secret and returns the associated public key
func GetPublicKeyFromSecret(secret string) []byte {
	secretHash := GetSHA256Hash(secret)
	pKey, _, _ := ed25519.GenerateKey(bytes.NewReader(secretHash[:sha256.Size]))

	return pKey
}

// GetAddressFromPublicKey takes a Lisk public key and returns the associated address
func GetAddressFromPublicKey(publicKey []byte) string {
	publicKeyHash := sha256.Sum256(publicKey)

	return GetBigNumberStringFromBytes(GetFirstEightBytesReversed(publicKeyHash[:sha256.Size])) + "L"
}
