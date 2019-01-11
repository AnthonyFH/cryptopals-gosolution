package main

import (
	"crypto/rand"
	ch "cryptohelpers"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

var superSecretKey []byte
var iv = []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
var blockSizeBytes = 16

// encryptPayload reads the strings in challengetext.txt,
// picks the one at the given index, and then encrypts it under a random key
// using AES-128-CBC
func encryptPayload(index int) ([]byte, error) {
	filename := "challengetext.txt"

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file %v", filename)
	}

	stringsFromFile, err := ioutil.ReadAll(file)

	stringList := strings.Split(string(stringsFromFile), "\n")
	messageList := make([][]byte, len(stringList), len(stringList))

	for i := 0; i < len(stringList); i++ {
		messageList[i], err = base64.StdEncoding.DecodeString(stringList[i])
		if err != nil {
			return nil, fmt.Errorf("error decoding hex string")
		}
	}

	// Generate a random key if needed
	if superSecretKey == nil {
		fmt.Println("GENERATED KEY")
		keyByteCount := 16
		superSecretKey = make([]byte, keyByteCount)
		rand.Read(superSecretKey)
	}

	if index > len(messageList) || index < 0 {
		return nil, errors.New("index out of range")
	}

	return ch.EncryptAESCBC(superSecretKey, iv, messageList[index])
}

// decryptPayloadAndCheckPadding decrypts the given cipher
// using the random key that was previously generated
// it then returns whether or not the padding is valid.
// Padding errors are swallowed.
func decryptPayloadAndCheckPadding(cipher []byte) (bool, error) {
	plaintext, err := ch.DecryptAESCBCLeavePadding(superSecretKey, iv, cipher)
	if err != nil {
		return false, fmt.Errorf("decryption error: %v", err)
	}

	_, err = ch.RemovePadding(plaintext)
	if err != nil {
		return false, nil
	}

	return true, nil
}

// decryptSingleByte decrypts the last block of cipherData by using access
// to a padding oracle.
func decryptSingleByte(cipherData []byte) ([]byte, error) {

	// NOTE: This function assumes that the cipherData is at least
	// two blocks large. Prepend the iv to the first block to use this function.

	// Take two blocks at the end of the cipher,
	// Then XOR the last byte by a known value until we have valid padding.
	// Then we "know" (worry about edge cases later)
	// that the last byte is '\x01' XOR'ed with that last byte
	// so we write that down, increment the last byte one (to induce '\x02')
	// and iterate through the next byte until we have valid padding
	// at which point we know that the second-to-last byte XOR'ed with the
	// current second-to-last value is '\x02' so we write down the value.
	// etc.

	decryptedBlock := make([]byte, 16)

	for i := 1; i <= blockSizeBytes; i++ {
		j := 0
		for j = 1; j < 256; j++ {
			cipherData[len(cipherData)-blockSizeBytes-i] ^= byte(j)
			validPadding, err := decryptPayloadAndCheckPadding(cipherData)
			if err != nil {
				return nil, fmt.Errorf("decryptionError: %v", err)
			}

			if validPadding {
				decryptedBlock[blockSizeBytes-i] = byte(i) ^ byte(j)
				// Set all the ending bytes to the next attack value
				for k := 1; k <= i; k++ {
					cipherData[len(cipherData)-blockSizeBytes-k] ^= byte(i) ^ byte(i+1)
				}

				break
			}
			// Put our modified byte back
			cipherData[len(cipherData)-blockSizeBytes-i] ^= byte(j)
		}
		if j == 256 {
			decryptedBlock[blockSizeBytes-i] = byte(i)
			// Set all the ending bytes to the next attack value
			for k := 1; k <= i; k++ {
				cipherData[len(cipherData)-blockSizeBytes-k] ^= byte(i) ^ byte(i+1)
			}
		}

	}

	return decryptedBlock, nil
}

func decryptCipherUserPaddingOracle(cipherData []byte) ([]byte, error) {
	var plaintext []byte
	numBlocks := len(cipherData) / blockSizeBytes

	// Prepend the iv so we can decrypt the first block by modifying it
	cipherData = append(iv, cipherData...)

	for i := 0; i < numBlocks; i++ {
		cipherDataCopy := make([]byte, len(cipherData))
		copy(cipherDataCopy, cipherData)
		decryptedBlock, err := decryptSingleByte(cipherDataCopy[:len(cipherDataCopy)-(i*blockSizeBytes)])
		if err != nil {
			return nil, fmt.Errorf("decryption error: %v", err)
		}
		plaintext = append(decryptedBlock, plaintext...)
	}

	return plaintext, nil
}

func main() {
	for i := 0; i < 10; i++ {
		cipherData, err := encryptPayload(i)
		if err != nil {
			panic("encryptRandomPayload error")
		}

		plaintext, err := decryptCipherUserPaddingOracle(cipherData)
		if err != nil {
			panic("decryption error")
		}

		fmt.Printf("plaintext at index %v: %v\n", i, plaintext)
		plaintext, err = ch.RemovePadding(plaintext)
		if err != nil {
			panic("padding error")
		}
		fmt.Printf("plaintext string at index %v: %v\n\n\n", i, string(plaintext))
	}
}
