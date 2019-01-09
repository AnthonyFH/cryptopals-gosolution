package main

import (
	ch "cryptohelpers"
	"encoding/hex"
	"fmt"
)

func main() {
	string1 := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	byte1, _ := hex.DecodeString(string1)

	// XOR the byte slice with every possible byte and save the probability that the result is English.
	tempSlice := make([]byte, len(byte1), len(byte1))
	probSlice := make([]int, 256, 256)
	for j := 0; j < 256; j++ {
		i := byte(j)
		copy(tempSlice, byte1)
		ch.ByteXor(tempSlice, i)
		probSlice[i] = ch.ProbEnglish(tempSlice)
	}

	// Find the index of the maximum probability
	max := 0
	index := byte(0)
	for j := 0; j < len(probSlice); j++ {
		i := byte(j)
		if probSlice[i] > max {
			max = probSlice[i]
			index = i
		}
	}

	ch.ByteXor(byte1, index)
	fmt.Println(string(byte1))
}
