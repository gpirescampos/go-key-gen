package gokeygen

import (
	"errors"

	"github.com/patcito/monero/base58"
	"github.com/patcito/monero/crypto"
)

var (
	InvalidSecret    = errors.New("invalid secret key")
	InvalidPublicKey = errors.New("invalid public key")
)

// Account contains public and private keys for the spend and view
// aspects of a Monero account.
type Account struct {
	spendP, spendS [32]byte
	viewP, viewS   [32]byte
}

// Address contains public keys for the spend and view aspects of a Monero account.
type Address struct {
	spend, view [32]byte
}

func (a *Address) String() string {
	text, _ := a.MarshalText()
	return string(text)
}

func (a *Address) MarshalText() (text []byte, err error) {
	data, _ := a.MarshalBinary()
	text = make([]byte, base58.EncodedLen(len(data)))
	base58.Encode(text, data)
	return text, nil
}

var Tag = byte(0x12)

func (a *Address) MarshalBinary() (data []byte, err error) {
	// make this long enough to hold a full hash on the end
	data = make([]byte, 104)
	// copy tag
	n := 1
	data[0] = Tag

	//copy keys
	copy(data[n:], a.spend[:])
	copy(data[n+32:], a.view[:])

	// checksum
	hash := crypto.NewHash()
	hash.Write(data[:n+64])
	// hash straight to the slice
	hash.Sum(data[:n+64])
	return data[:n+68], nil
}

// SecretFrom seed reduces a seed to a secret key.
func SecretFromSeed(secret, seed *[32]byte) { reduce32(secret, seed) }

// Recover recovers an account using a secret key.
func RecoverAccount(secret [32]byte) (*Account, error) {
	if !crypto.CheckSecret(&secret) {
		return nil, crypto.InvalidSecret
	}

	a := &Account{spendS: secret}
	crypto.PublicFromSecret(&a.spendP, &a.spendS)
	crypto.ViewFromSpend(&a.viewS, &a.spendS)
	crypto.PublicFromSecret(&a.viewP, &a.viewS)
	return a, nil
}

// Secret returns the spend secret key that
// can be used to regenerate the account.
func (a *Account) Secret() [32]byte {
	return a.spendS
}

// Address returns the address of a given account.
func (a *Account) Address() *Address {
	return &Address{spend: a.spendP, view: a.viewP}
}

func load3(b []byte) int64 {
	i := int64(b[0])
	i |= int64(b[1]) << 8
	i |= int64(b[2]) << 16
	return i
}

func load4(b []byte) int64 {
	i := int64(b[0])
	i |= int64(b[1]) << 8
	i |= int64(b[2]) << 16
	i |= int64(b[3]) << 24
	return i
}

// reduce32 reduces src[:32] to dst[:32].
// If src and dst are the same slice it will not affect the output.
func reduce32(dst, src *[32]byte) {
	s0 := int64(0x1fffff & load3(src[0:]))
	s1 := int64(0x1fffff & (load4(src[2:]) >> 5))
	s2 := int64(0x1fffff & (load3(src[5:]) >> 2))
	s3 := int64(0x1fffff & (load4(src[7:]) >> 7))
	s4 := int64(0x1fffff & (load4(src[10:]) >> 4))
	s5 := int64(0x1fffff & (load3(src[13:]) >> 1))
	s6 := int64(0x1fffff & (load4(src[15:]) >> 6))
	s7 := int64(0x1fffff & (load3(src[18:]) >> 3))
	s8 := int64(0x1fffff & load3(src[21:]))
	s9 := int64(0x1fffff & (load4(src[23:]) >> 5))
	s10 := int64(0x1fffff & (load3(src[26:]) >> 2))
	s11 := (load4(src[28:]) >> 7)
	s12 := int64(0)

	var (
		carry0, carry1, carry2, carry3   int64
		carry4, carry5, carry6, carry7   int64
		carry8, carry9, carry10, carry11 int64
	)

	carry0 = (s0 + (1 << 20)) >> 21
	s1 += carry0
	s0 -= carry0 << 21
	carry2 = (s2 + (1 << 20)) >> 21
	s3 += carry2
	s2 -= carry2 << 21
	carry4 = (s4 + (1 << 20)) >> 21
	s5 += carry4
	s4 -= carry4 << 21
	carry6 = (s6 + (1 << 20)) >> 21
	s7 += carry6
	s6 -= carry6 << 21
	carry8 = (s8 + (1 << 20)) >> 21
	s9 += carry8
	s8 -= carry8 << 21
	carry10 = (s10 + (1 << 20)) >> 21
	s11 += carry10
	s10 -= carry10 << 21

	carry1 = (s1 + (1 << 20)) >> 21
	s2 += carry1
	s1 -= carry1 << 21
	carry3 = (s3 + (1 << 20)) >> 21
	s4 += carry3
	s3 -= carry3 << 21
	carry5 = (s5 + (1 << 20)) >> 21
	s6 += carry5
	s5 -= carry5 << 21
	carry7 = (s7 + (1 << 20)) >> 21
	s8 += carry7
	s7 -= carry7 << 21
	carry9 = (s9 + (1 << 20)) >> 21
	s10 += carry9
	s9 -= carry9 << 21
	carry11 = (s11 + (1 << 20)) >> 21
	s12 += carry11
	s11 -= carry11 << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901
	s12 = 0

	carry0 = s0 >> 21
	s1 += carry0
	s0 -= carry0 << 21
	carry1 = s1 >> 21
	s2 += carry1
	s1 -= carry1 << 21
	carry2 = s2 >> 21
	s3 += carry2
	s2 -= carry2 << 21
	carry3 = s3 >> 21
	s4 += carry3
	s3 -= carry3 << 21
	carry4 = s4 >> 21
	s5 += carry4
	s4 -= carry4 << 21
	carry5 = s5 >> 21
	s6 += carry5
	s5 -= carry5 << 21
	carry6 = s6 >> 21
	s7 += carry6
	s6 -= carry6 << 21
	carry7 = s7 >> 21
	s8 += carry7
	s7 -= carry7 << 21
	carry8 = s8 >> 21
	s9 += carry8
	s8 -= carry8 << 21
	carry9 = s9 >> 21
	s10 += carry9
	s9 -= carry9 << 21
	carry10 = s10 >> 21
	s11 += carry10
	s10 -= carry10 << 21
	carry11 = s11 >> 21
	s12 += carry11
	s11 -= carry11 << 21

	s0 += s12 * 666643
	s1 += s12 * 470296
	s2 += s12 * 654183
	s3 -= s12 * 997805
	s4 += s12 * 136657
	s5 -= s12 * 683901

	carry0 = s0 >> 21
	s1 += carry0
	s0 -= carry0 << 21
	carry1 = s1 >> 21
	s2 += carry1
	s1 -= carry1 << 21
	carry2 = s2 >> 21
	s3 += carry2
	s2 -= carry2 << 21
	carry3 = s3 >> 21
	s4 += carry3
	s3 -= carry3 << 21
	carry4 = s4 >> 21
	s5 += carry4
	s4 -= carry4 << 21
	carry5 = s5 >> 21
	s6 += carry5
	s5 -= carry5 << 21
	carry6 = s6 >> 21
	s7 += carry6
	s6 -= carry6 << 21
	carry7 = s7 >> 21
	s8 += carry7
	s7 -= carry7 << 21
	carry8 = s8 >> 21
	s9 += carry8
	s8 -= carry8 << 21
	carry9 = s9 >> 21
	s10 += carry9
	s9 -= carry9 << 21
	carry10 = s10 >> 21
	s11 += carry10
	s10 -= carry10 << 21

	dst[0] = byte(s0 >> 0)
	dst[1] = byte(s0 >> 8)
	dst[2] = byte((s0 >> 16) | (s1 << 5))
	dst[3] = byte(s1 >> 3)
	dst[4] = byte(s1 >> 11)
	dst[5] = byte((s1 >> 19) | (s2 << 2))
	dst[6] = byte(s2 >> 6)
	dst[7] = byte((s2 >> 14) | (s3 << 7))
	dst[8] = byte(s3 >> 1)
	dst[9] = byte(s3 >> 9)
	dst[10] = byte((s3 >> 17) | (s4 << 4))
	dst[11] = byte(s4 >> 4)
	dst[12] = byte(s4 >> 12)
	dst[13] = byte((s4 >> 20) | (s5 << 1))
	dst[14] = byte(s5 >> 7)
	dst[15] = byte((s5 >> 15) | (s6 << 6))
	dst[16] = byte(s6 >> 2)
	dst[17] = byte(s6 >> 10)
	dst[18] = byte((s6 >> 18) | (s7 << 3))
	dst[19] = byte(s7 >> 5)
	dst[20] = byte(s7 >> 13)
	dst[21] = byte(s8 >> 0)
	dst[22] = byte(s8 >> 8)
	dst[23] = byte((s8 >> 16) | (s9 << 5))
	dst[24] = byte(s9 >> 3)
	dst[25] = byte(s9 >> 11)
	dst[26] = byte((s9 >> 19) | (s10 << 2))
	dst[27] = byte(s10 >> 6)
	dst[28] = byte((s10 >> 14) | (s11 << 7))
	dst[29] = byte(s11 >> 1)
	dst[30] = byte(s11 >> 9)
	dst[31] = byte(s11 >> 17)
}
