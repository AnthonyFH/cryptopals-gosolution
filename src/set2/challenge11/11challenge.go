package main

import (
	"crypto/aes"
	ch "cryptohelpers"
	"fmt"
)

func main() {
	// Go through 50 times and make sure we guess correctly ever time.
	for i := 0; i < 50; i++ {
		createCipherTextAndGuess()
	}
}

func createCipherTextAndGuess() {

	plainText := []byte("\x00")

	// We need a buffer of 16 bytes to consume the first block.
	// The encryption function will add at least 5 bytes, so we need
	// another 11 and we already have one so just append 10 more.
	//
	// Then append the plaintext we will use to compare in the second and third
	// block to see if this is ECB.
	for i := 0; i < 10+(aes.BlockSize*2); i++ {
		plainText = append(plainText, '\x00')
	}

	cipherText, randInt, err := ch.CBCECBEncryptionOracle(plainText)
	if err != nil {
		fmt.Println("Error with encryption oracle")
		return
	}

	// ECB = 1
	// CBC = 0
	// Default to guessing ECB. If the two blocks in the middle do not match, this is CBC.
	guess := 1
	for i := 0; i < aes.BlockSize; i++ {
		if cipherText[aes.BlockSize+i] != cipherText[aes.BlockSize*2+i] {
			guess = 0
			break
		}
	}

	if guess == 1 && randInt == 1 {
		// We correctly discovered this is ECB
		fmt.Println("Success: ECB")
	} else if guess == 0 && randInt == 0 {
		// We correctly discovered this is CBC
		fmt.Println("Success: CBC")
	} else {
		// We guessed incorrectly...
		fmt.Println("FAILURE!!!!!!!")
	}
	//fmt.Println(cipherText)
}
