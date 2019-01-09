package main

import (
	ch "cryptohelpers"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {

	// First check our Hamming distance implementation.
	inputSlice1 := "this is a test"
	byteSlice1 := []byte(inputSlice1)

	inputSlice2 := "wokka wokka!!!"
	byteSlice2 := []byte(inputSlice2)

	distance, err := ch.HammingDistance(byteSlice1, byteSlice2)

	if err != nil {
		panic("hammingDistance: " + err.Error())
	}

	fmt.Println("Hamming distance of the two example strings is: ", distance)

	// Now on to the actual problem.
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

	// First compute the probable key size.
	hamDistances := make([]int, 40, 40)
	hamDistancesNormalized := make([]float64, 40, 40)

	startingKeySize := 2
	min := float64(37) // what a hack
	minKeySize := 0
	for i := 0; i < len(hamDistances); i++ {
		hamDistances[i], err = ch.HammingDistanceOfFirstChunks(cipherBytes, i+startingKeySize)
		if err != nil {
			fmt.Println("Error computing hamming distance of first chunks:", err)
			return
		}
		hamDistancesNormalized[i] = (float64(hamDistances[i]) / float64(i))
		if hamDistancesNormalized[i] < min {
			min, minKeySize = hamDistancesNormalized[i], i+startingKeySize
		}
	}

	fmt.Println("Minimum Ham Distance, Key Size = ", min, minKeySize)

	// Now break the cipher text up so that each chunk only has a one byte key
	key := make([]byte, minKeySize, minKeySize)
	for i := 0; i < minKeySize; i++ {
		chunk := make([]byte, 0, (len(cipherBytes)/minKeySize)+1)
		for j := i; j < len(cipherBytes); j += minKeySize {
			chunk = append(chunk, cipherBytes[j])
			tempKey, err := ch.BreakSingleByteXor(chunk)
			key[i] = tempKey
			if err != nil {
				panic("breakingSingleByteXor error: " + err.Error())
			}
		}
	}

	fmt.Println(key)
	ch.RepeatingKeyXor(cipherBytes, key)

	fmt.Println(string(cipherBytes))
	fmt.Println(string(key))

}
