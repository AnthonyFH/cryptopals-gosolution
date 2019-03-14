package main

import (
	"crypto/rand"
	ch "cryptohelpers"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

var superSecretKey []byte
var nonce = []byte("\x00\x00\x00\x00\x00\x00\x00\x00")

func encryptCipherTexts() ([][]byte, error) {
	// Generate a random key if needed
	if superSecretKey == nil {
		fmt.Println("GENERATED KEY")
		keyByteCount := 16
		superSecretKey = make([]byte, keyByteCount)
		rand.Read(superSecretKey)
	}

	// File with a list of plaintext
	filename := "20.txt"

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}

	plaintexts, err := ioutil.ReadAll(file)

	plaintextList := strings.Split(string(plaintexts), "\n")
	cipherList := make([][]byte, len(plaintextList), len(plaintextList))

	for i := 0; i < len(plaintextList); i++ {
		plainText, err := base64.StdEncoding.DecodeString(plaintextList[i])
		if err != nil {
			return nil, fmt.Errorf("error decoding plaintext: %v", err)
		}
		cipherList[i], err = ch.EncryptDecryptAESCTR(superSecretKey, nonce, plainText)
		if err != nil {
			return nil, fmt.Errorf("error ecncrypting: %v", err)
		}
	}

	return cipherList, nil
}

func main() {

	cipherList, err := encryptCipherTexts()
	if err != nil {
		panic("problem")
	}

	// This will be the size of the key we will work on getting
	minCipherSize := len(cipherList[0])

	for i := 0; i < len(cipherList); i++ {
		if (len(cipherList[i])) < minCipherSize {
			minCipherSize = len(cipherList[i])
		}
	}

	// Build up the probable key one byte at a time by treting the concatenation
	// of cipher texts like a repeating-key XOR'ed cipher (which it is)
	key := make([]byte, minCipherSize, minCipherSize)
	for i := 0; i < minCipherSize; i++ {
		chunk := make([]byte, 0, len(cipherList))
		for j := i; j < len(cipherList); j++ {
			chunk = append(chunk, cipherList[j][i])
		}

		tempKey, err := ch.BreakSingleByteXor(chunk)
		key[i] = tempKey
		if err != nil {
			panic("breakingSingleByteXor error: " + err.Error())
		}
	}

	// Now get all the plaintexts that the probablyeKeyStream will produce
	probablePlaintextList := make([][]byte, len(cipherList))

	for i := 0; i < len(cipherList); i++ {
		probablePlaintextList[i], err = ch.FixedXor(cipherList[i][0:len(key)], key)
		if err != nil {
			panic("problem")
		}
	}

	for i := 0; i < len(probablePlaintextList); i++ {
		print(string(probablePlaintextList[i]))
		print("\n")
	}

	// TODO similar to the last one, this is not perfect, but good enough
	// the gaps can be filled in manually for now. I may improve the automatic part
	// later but not now.

}
