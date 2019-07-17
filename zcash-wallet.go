package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/FiloSottile/zcash-mini/bip39"
)

func fatal(v ...interface{}) {
	v = append([]interface{}{"[FATAL] Error:"}, v...)
	fmt.Fprintln(os.Stderr, v...)
	os.Exit(1)
}

func readMnemonic(menmonic string) []byte {
	words := strings.Split(menmonic, " ")
	if len(words) != 24 {
		fatal("a mnemonic must be 24 words long")
	}
	rawKey, corrections, err := bip39.Decode(words)
	if err != nil {
		fatal(err)
	}
	for _, c := range corrections {
		fmt.Fprintln(os.Stderr, "[INFO] Automatically corrected:", c)
	}
	return rawKey
}
