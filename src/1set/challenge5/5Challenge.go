package main

import (
	ch "cryptohelpers"
	"encoding/hex"
	"fmt"
)

func main() {
	inputSlice := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	byteSlice := []byte(inputSlice)

	ch.RepeatingKeyXor(byteSlice, []byte("ICE"))

	fmt.Println("The result of repeated XOR is:")
	fmt.Println(hex.EncodeToString(byteSlice))
}
