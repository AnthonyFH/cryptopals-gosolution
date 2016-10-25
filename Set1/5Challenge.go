package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	//	"io/ioutil"
	//	"os"
	//	"strings"
)

func main() {
	inputSlice := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	byteSlice := []byte(inputSlice)

	repeatingKeyXor(byteSlice, []byte("ICE"))

	fmt.Println("The result of repeated XOR is:")
	fmt.Println(hex.EncodeToString(byteSlice))
}

// Returns the maximum probability returned from probEnglish and also the byte that XOR's to get that probability.
// Return values should only be used to compare with other return values of probEnglish.
func probIsEncrypted(byteSlice []byte) (int, byte, error) {

	// XOR the byte slice with every possible byte and save the probability that the result is English.
	tempSlice := make([]byte, len(byteSlice), len(byteSlice))
	probSlice := make([]int, 256, 256)
	for j := 0; j < 256; j++ {
		i := byte(j)
		copy(tempSlice, byteSlice)
		byteXor(tempSlice, i)
		probSlice[i] = probEnglish(tempSlice)
	}

	// Find the index of the maximum probability.
	max := 0
	index := byte(0)
	for j := 0; j < len(probSlice); j++ {
		i := byte(j)
		if probSlice[i] > max {
			max = probSlice[i]
			index = i
		}
	}

	return max, index, nil
}

// Takes a  byte slice and in-place xor's it with the given byte.
func byteXor(byteSlice []byte, xorByte byte) error {
	for i := 0; i < len(byteSlice); i++ {
		tempByte := byteSlice[i]
		tempByte ^= xorByte
		byteSlice[i] = tempByte
	}

	return nil
}

// Takes to bytes and xor's them together, returning the result.
func fixedXor(byte1, byte2 []byte) ([]byte, error) {

	result := make([]byte, len(byte1), len(byte1))

	if len(byte1) != len(byte2) {
		return nil, errors.New("Byte lenghts do not match")
	}

	for i := 0; i < len(byte1); i++ {
		result[i] = byte1[i] ^ byte2[i]
	}
	return result, nil
}

// Returns an integer representing the probability that the ASCII string represented by byteSlice is English.
// This is VERY hacky and does not truly return a probability. Return values should
// only be used to compare to other return values of this function.
func probEnglish(byteSlice []byte) int {
	result := 0
	for i := 0; i < len(byteSlice); i++ {

		if byteSlice[i] < byte(' ') {
			result -= 20
		}

		if byteSlice[i] > byte('z') {
			result -= 20
		}

		// A list of English characters in order of increasing frequency in typical words
		probString := "zZqQxXjJkKvVbBpPyYgGfFwWmMuUcClLdDrRhHsSnNiIoOaAtTeE"

		for j := 0; j < len(probString); j++ {
			if byteSlice[i] == probString[j] {
				result += j
			}
		}
	}

	return result
}

// Takes a slice of bytes and in-place XOR's it with the repeated key
func repeatingKeyXor(inputSlice []byte, key []byte) error {
	j := 0
	for i := 0; i < len(inputSlice); i++ {
		if j == len(key) {
			j = 0
		}

		tempByte := inputSlice[i]
		tempByte = tempByte ^ key[j]
		inputSlice[i] = tempByte

		j++
	}

	return nil
}
