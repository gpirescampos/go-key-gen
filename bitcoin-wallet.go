package gokeygen

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

var (
	//MainNet
	Public  []byte
	Private []byte
	//TestNet
	TestPublic  []byte
	TestPrivate []byte
)

func init() {
	Public, _ = hex.DecodeString("0488B21E")
	Private, _ = hex.DecodeString("0488ADE4")
	TestPublic, _ = hex.DecodeString("043587CF")
	TestPrivate, _ = hex.DecodeString("04358394")
}

// HDWallet defines the components of a hierarchical deterministic wallet
type HDWallet struct {
	Vbytes      []byte //4 bytes
	Depth       uint16 //1 byte
	Fingerprint []byte //4 bytes
	I           []byte //4 bytes
	Chaincode   []byte //32 bytes
	Key         []byte //33 bytes
}

// Child returns the ith child of wallet w. Values of i >= 2^31
// signify private key derivation. Attempting private key derivation
// with a public key will throw an error.
func (w *HDWallet) Child(i uint32) (*HDWallet, error) {
	var fingerprint, I, newkey []byte
	switch {
	case bytes.Compare(w.Vbytes, Private) == 0, bytes.Compare(w.Vbytes, TestPrivate) == 0:
		pub := privToPub(w.Key)
		mac := hmac.New(sha512.New, w.Chaincode)
		if i >= uint32(0x80000000) {
			mac.Write(append(w.Key, uint32ToByte(i)...))
		} else {
			mac.Write(append(pub, uint32ToByte(i)...))
		}
		I = mac.Sum(nil)
		iL := new(big.Int).SetBytes(I[:32])
		if iL.Cmp(curve.N) >= 0 || iL.Sign() == 0 {
			return &HDWallet{}, errors.New("Invalid Child")
		}
		newkey = addPrivKeys(I[:32], w.Key)
		fingerprint = hash160(privToPub(w.Key))[:4]

	case bytes.Compare(w.Vbytes, Public) == 0, bytes.Compare(w.Vbytes, TestPublic) == 0:
		mac := hmac.New(sha512.New, w.Chaincode)
		if i >= uint32(0x80000000) {
			return &HDWallet{}, errors.New("Can't do Private derivation on Public key!")
		}
		mac.Write(append(w.Key, uint32ToByte(i)...))
		I = mac.Sum(nil)
		iL := new(big.Int).SetBytes(I[:32])
		if iL.Cmp(curve.N) >= 0 || iL.Sign() == 0 {
			return &HDWallet{}, errors.New("Invalid Child")
		}
		newkey = addPubKeys(privToPub(I[:32]), w.Key)
		fingerprint = hash160(w.Key)[:4]
	}
	return &HDWallet{w.Vbytes, w.Depth + 1, fingerprint, uint32ToByte(i), I[32:], newkey}, nil
}

// Serialize returns the serialized form of the wallet.
func (w *HDWallet) Serialize() []byte {
	depth := uint16ToByte(uint16(w.Depth % 256))
	//bindata = vbytes||depth||fingerprint||i||chaincode||key
	bindata := make([]byte, 78)
	copy(bindata, w.Vbytes)
	copy(bindata[4:], depth)
	copy(bindata[5:], w.Fingerprint)
	copy(bindata[9:], w.I)
	copy(bindata[13:], w.Chaincode)
	copy(bindata[45:], w.Key)
	chksum := dblSha256(bindata)[:4]
	return append(bindata, chksum...)
}

// String returns the base58-encoded string form of the wallet.
func (w *HDWallet) String() string {
	return base58.Encode(w.Serialize())
}

// StringWallet returns a wallet given a base58-encoded extended key
func StringWallet(data string) (*HDWallet, error) {
	dbin := base58.Decode(data)
	if err := ByteCheck(dbin); err != nil {
		return &HDWallet{}, err
	}
	if bytes.Compare(dblSha256(dbin[:(len(dbin) - 4)])[:4], dbin[(len(dbin)-4):]) != 0 {
		return &HDWallet{}, errors.New("Invalid checksum")
	}
	vbytes := dbin[0:4]
	depth := byteToUint16(dbin[4:5])
	fingerprint := dbin[5:9]
	i := dbin[9:13]
	chaincode := dbin[13:45]
	key := dbin[45:78]
	return &HDWallet{vbytes, depth, fingerprint, i, chaincode, key}, nil
}

// Pub returns a new wallet which is the public key version of w.
// If w is a public key, Pub returns a copy of w
func (w *HDWallet) Pub() *HDWallet {
	if bytes.Compare(w.Vbytes, Public) == 0 {
		return &HDWallet{w.Vbytes, w.Depth, w.Fingerprint, w.I, w.Chaincode, w.Key}
	} else {
		return &HDWallet{Public, w.Depth, w.Fingerprint, w.I, w.Chaincode, privToPub(w.Key)}
	}
}

// StringChild returns the ith base58-encoded extended key of a base58-encoded extended key.
func StringChild(data string, i uint32) (string, error) {
	w, err := StringWallet(data)
	if err != nil {
		return "", err
	} else {
		w, err = w.Child(i)
		if err != nil {
			return "", err
		} else {
			return w.String(), nil
		}
	}
}

//StringAddress returns the Bitcoin address of a base58-encoded extended key.
func StringAddress(data string) (string, error) {
	w, err := StringWallet(data)
	if err != nil {
		return "", err
	} else {
		return w.Address(), nil
	}
}

// Address returns bitcoin address represented by wallet w.
func (w *HDWallet) Address() string {
	x, y := expand(w.Key)
	four, _ := hex.DecodeString("04")
	padded_key := append(four, append(x.Bytes(), y.Bytes()...)...)
	var prefix []byte
	if bytes.Compare(w.Vbytes, TestPublic) == 0 || bytes.Compare(w.Vbytes, TestPrivate) == 0 {
		prefix, _ = hex.DecodeString("6F")
	} else {
		prefix, _ = hex.DecodeString("00")
	}
	addr_1 := append(prefix, hash160(padded_key)...)
	chksum := dblSha256(addr_1)
	return base58.Encode(append(addr_1, chksum[:4]...))
}

// GenSeed returns a random seed with a length measured in bytes.
// The length must be at least 128.
func GenSeed(length int) ([]byte, error) {
	b := make([]byte, length)
	if length < 128 {
		return b, errors.New("length must be at least 128 bits")
	}
	_, err := rand.Read(b)
	return b, err
}

// MasterKey returns a new wallet given a random seed.
func MasterKey(seed []byte) *HDWallet {
	key := []byte("Bitcoin seed")
	mac := hmac.New(sha512.New, key)
	mac.Write(seed)
	I := mac.Sum(nil)
	secret := I[:len(I)/2]
	chain_code := I[len(I)/2:]
	depth := 0
	i := make([]byte, 4)
	fingerprint := make([]byte, 4)
	zero := make([]byte, 1)
	return &HDWallet{Private, uint16(depth), fingerprint, i, chain_code, append(zero, secret...)}
}

// StringCheck is a validation check of a base58-encoded extended key.
func StringCheck(key string) error {
	return ByteCheck(base58.Decode(key))
}

func ByteCheck(dbin []byte) error {
	// check proper length
	if len(dbin) != 82 {
		return errors.New("invalid string")
	}
	// check for correct Public or Private vbytes
	if bytes.Compare(dbin[:4], Public) != 0 && bytes.Compare(dbin[:4], Private) != 0 && bytes.Compare(dbin[:4], TestPublic) != 0 && bytes.Compare(dbin[:4], TestPrivate) != 0 {
		return errors.New("invalid string")
	}
	// if Public, check x coord is on curve
	x, y := expand(dbin[45:78])
	if bytes.Compare(dbin[:4], Public) == 0 || bytes.Compare(dbin[:4], TestPublic) == 0 {
		if !onCurve(x, y) {
			return errors.New("invalid string")
		}
	}
	return nil
}

var curve *btcec.KoblitzCurve = btcec.S256()

func hash160(data []byte) []byte {
	sha := sha256.New()
	ripe := ripemd160.New()
	sha.Write(data)
	ripe.Write(sha.Sum(nil))
	return ripe.Sum(nil)
}

func dblSha256(data []byte) []byte {
	sha1 := sha256.New()
	sha2 := sha256.New()
	sha1.Write(data)
	sha2.Write(sha1.Sum(nil))
	return sha2.Sum(nil)
}

func privToPub(key []byte) []byte {
	return compress(curve.ScalarBaseMult(key))
}

func onCurve(x, y *big.Int) bool {
	return curve.IsOnCurve(x, y)
}

func compress(x, y *big.Int) []byte {
	two := big.NewInt(2)
	rem := two.Mod(y, two).Uint64()
	rem += 2
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(rem))
	rest := x.Bytes()
	pad := 32 - len(rest)
	if pad != 0 {
		zeroes := make([]byte, pad)
		rest = append(zeroes, rest...)
	}
	return append(b[1:], rest...)
}

//2.3.4 of SEC1 - http://www.secg.org/index.php?action=secg,docs_secg
func expand(key []byte) (*big.Int, *big.Int) {
	params := curve.Params()
	exp := big.NewInt(1)
	exp.Add(params.P, exp)
	exp.Div(exp, big.NewInt(4))
	x := big.NewInt(0).SetBytes(key[1:33])
	y := big.NewInt(0).SetBytes(key[:1])
	beta := big.NewInt(0)
	beta.Exp(x, big.NewInt(3), nil)
	beta.Add(beta, big.NewInt(7))
	beta.Exp(beta, exp, params.P)
	if y.Add(beta, y).Mod(y, big.NewInt(2)).Int64() == 0 {
		y = beta
	} else {
		y = beta.Sub(params.P, beta)
	}
	return x, y
}

func addPrivKeys(k1, k2 []byte) []byte {
	i1 := big.NewInt(0).SetBytes(k1)
	i2 := big.NewInt(0).SetBytes(k2)
	i1.Add(i1, i2)
	i1.Mod(i1, curve.Params().N)
	k := i1.Bytes()
	zero, _ := hex.DecodeString("00")
	return append(zero, k...)
}

func addPubKeys(k1, k2 []byte) []byte {
	x1, y1 := expand(k1)
	x2, y2 := expand(k2)
	return compress(curve.Add(x1, y1, x2, y2))
}

func uint32ToByte(i uint32) []byte {
	a := make([]byte, 4)
	binary.BigEndian.PutUint32(a, i)
	return a
}

func uint16ToByte(i uint16) []byte {
	a := make([]byte, 2)
	binary.BigEndian.PutUint16(a, i)
	return a[1:]
}

func byteToUint16(b []byte) uint16 {
	if len(b) == 1 {
		zero := make([]byte, 1)
		b = append(zero, b...)
	}
	return binary.BigEndian.Uint16(b)
}
