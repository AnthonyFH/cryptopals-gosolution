package main

import (
	ch "cryptohelpers"
	"encoding/hex"
	"fmt"
)

func main() {
	string1 := "1c0111001f010100061a024b53535009181c"
	string2 := "686974207468652062756c6c277320657965"
	byte1, _ := hex.DecodeString(string1)
	byte2, _ := hex.DecodeString(string2)
	result, _ := ch.FixedXor(byte1, byte2)
	fmt.Printf("%X\n", result)
}
