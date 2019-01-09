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
var iv = []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
var blockSizeBytes = 16

// encryptRandomPayload reads the strings in challengetext.txt,
// picks one at random, and then encrypts it under a random key
// using AES-128-CBC
func encryptRandomPayload() ([]byte, error) {
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

	randomByteSlice := make([]byte, 1)
	rand.Read(randomByteSlice)

	return ch.EncryptAESCBC(superSecretKey, iv, messageList[int(randomByteSlice[0])%len(messageList)])
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

func decryptSingleByte(cipherData []byte) ([]byte, error) {

	// TODO:
	// - for now assuming that cipherData is at least two blocks large
	// - don't worry about edge cases where valid padding is because of 2's or 3's and so on

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
		// TODO handle when there is no match here and the last byte is already \x01
		for j := 1; j < 256; j++ {
			cipherData[len(cipherData)-blockSizeBytes-i] ^= byte(j)
			validPadding, err := decryptPayloadAndCheckPadding(cipherData)
			if err != nil {
				return nil, fmt.Errorf("decryptionError: %v", err)
			}

			if validPadding {
				decryptedBlock[blockSizeBytes-i] = byte(i) ^ byte(j)
				// Set all the ending bytes to the next attack value
				for k := 1; k <= i; k++ {
					// TODO TODO, was working here and it's mostly working, but we always
					// get back a decrypted block that has one less padding value than it should (e.g. 4 4 4)
					cipherData[len(cipherData)-blockSizeBytes-k] ^= byte(i) ^ byte(i+1)
				}

				break
			}
			// Put our modified byte back
			cipherData[len(cipherData)-blockSizeBytes-i] ^= byte(j)
		}
	}

	return decryptedBlock, nil
}

func main() {
	cipherData, err := encryptRandomPayload()
	if err != nil {
		panic("encryptRandomPayload error")
	}

	// TODO call this correctly to get the whole thing
	decryptedBlock, err := decryptSingleByte(cipherData)
	if err != nil {
		panic("decryptionerror")
	}

	fmt.Printf("decryptedBlock: %v\n", decryptedBlock)
	fmt.Printf("decryptedBlock string: %v\n", string(decryptedBlock))
}
