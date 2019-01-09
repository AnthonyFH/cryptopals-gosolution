package main

import (
	"crypto/rand"
	ch "cryptohelpers"
	"errors"
	"fmt"
	"strings"
)

var superSecretKey []byte
var iv = []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
var prependTextBytes = []byte("comment1=cooking%20MCs;userdata=")
var adminTextBytes = []byte(";admin=true;")
var appendTextBytes = []byte(";comment2=%20like%20a%20pound%20of%20bacon")
var blockSizeBytes = 16
var semiColonEscapeSequence = []byte("%3B")
var equalsEscapeSequence = []byte("%3D")

// createEncryptedCbcPayload takes in some plaintext, quotes out ';' and '=' characters,
// prepends and appends the text specified in Challenge 16, and then pads the result and
// encrypts it using AES-CBC with a random key.
func createEncryptedCbcPayload(userData []byte) ([]byte, error) {

	// Generate a random key if needed
	if superSecretKey == nil {
		fmt.Println("GENERATED KEY")
		keyByteCount := blockSizeBytes
		superSecretKey = make([]byte, keyByteCount)
		rand.Read(superSecretKey)
	}

	var escapedDataBuilder strings.Builder

	// Escape userData
	for i := 0; i < len(userData); i++ {
		if userData[i] == byte(';') {
			escapedDataBuilder.Write(semiColonEscapeSequence)
		} else if userData[i] == byte('=') {
			escapedDataBuilder.Write(equalsEscapeSequence)
		} else {
			escapedDataBuilder.WriteByte(userData[i])
		}
	}

	// Append the strings together
	encryptionPayload := append(prependTextBytes, escapedDataBuilder.String()...)
	encryptionPayload = append(encryptionPayload, appendTextBytes...)
	encryptionPayload, err := ch.AppendPadding(encryptionPayload, blockSizeBytes)
	if err != nil {
		return nil, fmt.Errorf("createEncryptedCbcPayload error %v", err)
	}

	// Encrypt and return
	return ch.EncryptAESCBC(superSecretKey, iv, encryptionPayload)
}

// decryptAndDecideIsAdmin takes the encrypted user data in cipherData,
// decryptes it using the previously generated AES key and then returns
// whether or not the resulting payload has the substring ";admin=true;"
func decryptAndDecideIsAdmin(cipherData []byte) (bool, error) {

	if superSecretKey == nil {
		return false, errors.New("superSecretKey is null")
	}
	plainTextBytes, err := ch.DecryptAESCBC(superSecretKey, iv, cipherData)
	if err != nil {
		return false, fmt.Errorf("DecryptionError: %v", err)
	}

	plainTextString := string(plainTextBytes)

	fmt.Printf("Decrypted data: %v\n", plainTextString)

	return strings.Contains(plainTextString, string(adminTextBytes)), nil
}

func main() {
	// What we want is to pad to an offset like so
	// "prependText || padding || myattackblock || a block that mostly contains admin=true with leftover ||appendtext"

	// Calculate how much padding we need
	prependPaddingSize := len(prependTextBytes) % blockSizeBytes

	// Construct the attack buffer
	// 1 - add padding at the beginning
	// 2 - add two blocks of 'a's
	attackPayload := make([]byte, 0)
	for i := 0; i < prependPaddingSize+2*blockSizeBytes; i++ {
		attackPayload = append(attackPayload, byte('a')) // add padding and padding block
	}

	cipherData, err := createEncryptedCbcPayload(attackPayload)
	if err != nil {
		panic("creatingPayloadIssue")
	}

	// Do the proper bit twiddling
	beginningindex := len(prependTextBytes) + prependPaddingSize
	for i := 0; i < len(adminTextBytes); i++ {
		// We know that we filled these bytes with 'a's and what we want is adminTextBytes[index]
		// So to get it we need to calculate 'a' ^ adminTextBytes and then XOR that with the current cipherData.
		cipherData[beginningindex+i] ^= (adminTextBytes[i] ^ byte('a'))
	}

	cipherHasAdmin, err := decryptAndDecideIsAdmin(cipherData)
	if err != nil {
		panic("decryptionError")
	} else if cipherHasAdmin {
		fmt.Println("----SUCCESS: WE ARE ADMIN-------")
	} else {
		fmt.Println("FAILURE :(")
	}
}
