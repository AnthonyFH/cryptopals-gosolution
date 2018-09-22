package main

import (
	"crypto/rand"
	ch "cryptohelpers"
	"encoding/base64"
	"errors"
	"fmt"
)

var secretText = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
var superSecretKey []byte

// decipherNextByte takes in the plaintext we have decoded so far and returns it appended to the input
// It assumes that encryptionFunc is a function that encrypts the input prepended to some unknown and static text.
func decipherNextByte(plainTextSoFar []byte, blockSizeBytes int, encryptionFunc func([]byte) ([]byte, error)) ([]byte, error) {

	fullBlocksDeciphered := len(plainTextSoFar) / blockSizeBytes

	// We need bytes one less than a block when appended to the plainTextSoFar
	bytesNeeded := blockSizeBytes - (len(plainTextSoFar) % blockSizeBytes) - 1

	plainTextBytesRoot := make([]byte, 0)

	for i := 0; i < bytesNeeded; i++ {
		plainTextBytesRoot = append(plainTextBytesRoot, byte('\x00'))
	}

	actualCipherTextBytes, err := appendingOracle(plainTextBytesRoot)
	if err != nil {
		return nil, fmt.Errorf("appendingOracle invocation error: %v", err)
	}

	var outputBlocks [256][]byte
	testPlainTextBytesInput := append(plainTextBytesRoot, plainTextSoFar...)
	testPlainTextBytesInput = append(testPlainTextBytesInput, byte(0)) // start out with a value of 0 at the end
	testPlainTextBytesInput = testPlainTextBytesInput[blockSizeBytes*fullBlocksDeciphered : blockSizeBytes*(fullBlocksDeciphered+1)]

	for i := 0; i < 256; i++ {
		testPlainTextBytesInput[blockSizeBytes-1] = byte(i)
		outputBlocks[i], err = appendingOracle(testPlainTextBytesInput)
		if err != nil {
			return nil, fmt.Errorf("appendingOracle invocation error: %v", err)
		}

	}

	matchIndex := -1
	for i := 1; i < 256 && matchIndex == -1; i++ {
		for j := 0; j < blockSizeBytes; j++ {
			if outputBlocks[i][j] != actualCipherTextBytes[j+(blockSizeBytes*fullBlocksDeciphered)] {
				break
			} else if j == blockSizeBytes-1 {
				matchIndex = i
			}
		}
	}

	if matchIndex == -1 {
		panic(errors.New("did not find a match"))
	}

	plainTextSoFar = append(plainTextSoFar, byte(matchIndex))

	return plainTextSoFar, nil
}

func appendingOracle(plainText []byte) ([]byte, error) {
	// Generate a random key if needed
	if superSecretKey == nil {
		fmt.Println("GENERATED KEY")
		keyByteCount := 16
		superSecretKey = make([]byte, keyByteCount)
		rand.Read(superSecretKey)
	}

	secretTextBinary, err := base64.StdEncoding.DecodeString(secretText)
	if err != nil {
		return nil, fmt.Errorf("appendingOracle base64 decode: %v", err)
	}

	appendedPlainText := append(plainText, secretTextBinary...)
	cipherText, err := ch.EncryptAESECB(superSecretKey, appendedPlainText)
	if err != nil {
		return nil, fmt.Errorf("appendingOracle encrypt: %v", err)
	}

	return cipherText, nil
}

func main() {

	plainTextBytes := []byte("\x00")

	blockSizeBytes := 0
	hasChanged := false
	changedSize := 0

	cipherTextBytes, err := appendingOracle(plainTextBytes)
	if err != nil {
		fmt.Printf("appendingOracle invocation error: %v\n", err)
	}

	// Loop until the output changes size twice
	for blockSizeBytes == 0 {
		plainTextBytes = append(plainTextBytes, byte('\x00'))
		cipherTextBytes1, err := appendingOracle(plainTextBytes)
		if err != nil {
			fmt.Printf("appendingOracle invocation error: %v\n", err)
		}

		if len(cipherTextBytes) != len(cipherTextBytes1) {
			if hasChanged {
				blockSizeBytes = len(cipherTextBytes1) - changedSize
			} else {
				hasChanged = true
				changedSize = len(cipherTextBytes1)
			}
		}

		cipherTextBytes = cipherTextBytes1
	}

	fmt.Printf("changedSize: %v\n", changedSize)
	fmt.Printf("blockSizeBytes: %v\n", blockSizeBytes)

	// Figure out if it's ECB
	isECB, err := ch.IsECB(appendingOracle)

	if isECB {
		fmt.Println("YEP, ECB")
	} else {
		fmt.Println("NOPE, NOT ECB")
	}

	decipheredPlainTextBytes := make([]byte, 0)
	finished := false

	for finished == false {
		decipheredPlainTextBytes, err = decipherNextByte(decipheredPlainTextBytes, blockSizeBytes, appendingOracle)
		_, err := ch.RemovePadding(decipheredPlainTextBytes)
		if err == nil {
			finished = true
		}
	}

	decipheredPlainTextBytes, err = ch.RemovePadding(decipheredPlainTextBytes)

	decipheredString := string(decipheredPlainTextBytes)
	fmt.Printf("decipheredString: %v\n", decipheredString)
}
