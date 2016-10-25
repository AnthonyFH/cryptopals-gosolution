package main

import (
	//  "encoding/hex"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	inputSlice1 := "this is a test"
	byteSlice1 := []byte(inputSlice1)

	inputSlice2 := "wokka wokka!!!"
	byteSlice2 := []byte(inputSlice2)

	distance, err := hammingDistance(byteSlice1, byteSlice2)

	if err != nil {
		panic("hammingDistance: " + err.Error())
	}

	fmt.Println("Hamming distance of the two example strings is: ", distance)

	filename := "6.txt"

	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file", filename)
		return
	}

	cipher, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println("Error reading file", filename)
		return
	}

	cipherString := string(cipher)

	cipherString = strings.Replace(cipherString, "\n", "", -1)

	cipherBytes, err := base64.StdEncoding.DecodeString(cipherString)
	if err != nil {
		fmt.Println("Error decoding cipher")
		return
	}

	hamDistances := make([]int, 40, 40)
	hamDistancesNormalized := make([]float64, 40, 40)

	startingKeySize := 2
	min := float64(37) // what a hack
	minKeySize := 0
	for i := 0; i < len(hamDistances); i++ {
		hamDistances[i], err = hammingDistanceOfFirstChunks(cipherBytes, i+startingKeySize)
		if err != nil {
			fmt.Println("Error computing hamming distance of first chunks:", err)
			return
		}
		hamDistancesNormalized[i] = (float64(hamDistances[i]) / float64(i))
		if hamDistancesNormalized[i] < min {
			min, minKeySize = hamDistancesNormalized[i], i+startingKeySize
		}
	}

	fmt.Println("Minimum Ham Distance, Key Size", min, minKeySize)

}

// Takes the first two chunks of size keysize of bChiper and computes their Hamming Distance
func hammingDistanceOfFirstChunks(bCipher []byte, keySize int) (int, error) {
	if len(bCipher) < 2*keySize {
		return -1, errors.New("bCipher is too short")
	}
	byteSlice1 := bCipher[0:keySize]
	byteSlice2 := bCipher[keySize : 2*keySize]

	return hammingDistance(byteSlice1, byteSlice2)
}

// Computes the Hamming Distance between two different byte slices of equal length.
func hammingDistance(byteSlice1, byteSlice2 []byte) (int, error) {
	if len(byteSlice1) != len(byteSlice2) {
		return -1, errors.New("Byte lengths do not match")
	}

	result := 0

	for i := 0; i < len(byteSlice1); i++ {
		xorByte := byteSlice1[i] ^ byteSlice2[i]

		for xorByte != 0 {
			result += 1
			xorByte &= xorByte - 1
		}
	}

	return result, nil
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
		return nil, errors.New("Byte lengths do not match")
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
