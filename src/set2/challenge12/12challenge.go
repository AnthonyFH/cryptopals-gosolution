package main

import (
	"crypto/rand"
	ch "cryptohelpers"
	"encoding/base64"
	"fmt"
)

var secretText = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
var superSecretKey []byte

func appendingOracle(plainText []byte) ([]byte, error) {
	// Generate a random key if needed
	if superSecretKey == nil {
		keyByteCount := 16
		superSecretKey = make([]byte, keyByteCount)
		rand.Read(superSecretKey)
	}

	secretTextBinary, err := base64.StdEncoding.DecodeString(secretText)
	if err != nil {
		return nil, fmt.Errorf("apenddingOracle base64 decode: %v", err)
	}

	appendedPlainText := append(plainText, secretTextBinary...)
	cipherText, err := ch.EncryptAESECB(superSecretKey, appendedPlainText)
	if err != nil {
		return nil, fmt.Errorf("apenddingOracle encrypt: %v", err)
	}

	return cipherText, nil
}

func main() {

	plainTextBytes := []byte("\x00")

	blockSize := 0
	hasChanged := false
	changedSize := 0

	cipherTextBytes, err := appendingOracle(plainTextBytes)
	if err != nil {
		fmt.Printf("appendingOracle invocation error: %v\n", err)
	}

	// Loop until the output changes size twice
	for blockSize == 0 {
		plainTextBytes = append(plainTextBytes, byte('\x00'))
		cipherTextBytes1, err := appendingOracle(plainTextBytes)
		if err != nil {
			fmt.Printf("appendingOracle invocation error: %v\n", err)
		}

		if len(cipherTextBytes) != len(cipherTextBytes1) {
			if hasChanged {
				blockSize = len(cipherTextBytes1) - changedSize
			} else {
				hasChanged = true
				changedSize = len(cipherTextBytes1)
			}
		}

		cipherTextBytes = cipherTextBytes1
		fmt.Printf("cipher: %v\n", cipherTextBytes)
	}

	fmt.Printf("changedSize: %v\n", changedSize)
	fmt.Printf("blockSize: %v\n", blockSize)

	// Figure out if it's ECB
	isECB, err := ch.IsECB(appendingOracle)

	if isECB {
		fmt.Println("YEP, ECB")
	} else {
		fmt.Println("NOPE, NOT ECB")
	}

	// Craft an input one byte short of a block
	plainTextBytes = []byte("\x00")
	for i := 0; i < blockSize-1; i++ {
		plainTextBytes = append(plainTextBytes, byte('\x00'))
	}

	cipherTextBytes, err = appendingOracle(plainTextBytes)

}
