package main

import (
	"crypto/rand"
	ca "cryptoattackers"
	ch "cryptohelpers"
	"errors"
	"fmt"
	"math/big"
)

var secretText = "This text is so secret.... shhh!!!"
var randomPrefix []byte
var superSecretKey []byte

// decipherNextByte takes in the plaintext we have decoded so far and the random prefix length and returns it appended to the input
// It assumes that encryptionFunc is a function that encrypts the input prepended to some unknown and static text.
func decipherNextByte(plainTextSoFar []byte, prefixSize int, blockSizeBytes int, encryptionFunc func([]byte) ([]byte, error)) ([]byte, error) {

	// The amount of full blocks in the output that we skip over to get to the interesting output byte
	fullBlocksToIndex := (prefixSize + len(plainTextSoFar)) / blockSizeBytes
	bytesToIndex := blockSizeBytes * fullBlocksToIndex

	// We need bytes one less than a block when prepended to the plainTextSoFar
	bytesNeeded := blockSizeBytes - ((prefixSize + len(plainTextSoFar)) % blockSizeBytes) - 1

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

	for i := 0; i < 256; i++ {
		testPlainTextBytesInput[len(testPlainTextBytesInput)-1] = byte(i)
		outputBlocks[i], err = appendingOracle(testPlainTextBytesInput)
		if err != nil {
			return nil, fmt.Errorf("appendingOracle invocation error: %v", err)
		}

	}

	matchIndex := -1
	for i := 0; i < 256 && matchIndex == -1; i++ {
		for j := 0; j < blockSizeBytes; j++ {
			if outputBlocks[i][j+bytesToIndex] != actualCipherTextBytes[j+bytesToIndex] {
				break
			} else if j == blockSizeBytes-1 {
				matchIndex = i
			}
		}
	}

	if matchIndex == -1 {
		panic(errors.New("did not find a match in decipherNextByte"))
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

	// Generate the random prefix if needed
	if len(randomPrefix) == 0 {
		randSize, err := rand.Int(rand.Reader, big.NewInt(100))
		if err != nil {
			panic("Error generating randomPrefix")
		}

		randomPrefix = make([]byte, randSize.Int64())
		rand.Read(randomPrefix)
		fmt.Printf("GENERATED PREFIX of size %v\n", randSize)
	}

	secretTextBinary := []byte(secretText)

	appendedPlainText := append(randomPrefix, plainText...)
	appendedPlainText = append(appendedPlainText, secretTextBinary...)
	cipherText, err := ch.EncryptAESECB(superSecretKey, appendedPlainText)
	if err != nil {
		return nil, fmt.Errorf("appendingOracle encrypt: %v", err)
	}

	return cipherText, nil
}

func main() {

	blockSizeBytes, err := ca.DetermineBlockSize(appendingOracle)
	if err != nil {
		fmt.Printf("DetermineBlockSize invocation error: %v\n", err)
	}

	fmt.Printf("blockSizeBytes: %v\n", blockSizeBytes)

	// Figure out if it's ECB
	isECB, err := ch.IsECB(appendingOracle)

	if isECB {
		fmt.Println("YEP, ECB")
	} else {
		fmt.Println("NOPE, NOT ECB")
	}

	// Find out how many bytes are in the randomPrefix
	randomPrefixSize := 0
	{
		inputPlainText := make([]byte, 0)
		outputCipher, err := appendingOracle(inputPlainText)
		if err != nil {
			fmt.Printf("appendingOracle invocation error: %v\n", err)
		}

		inputPlainText = append(inputPlainText, byte(0)) // append a single byte to see where it creates a difference
		outputCipher1, err := appendingOracle(inputPlainText)
		if err != nil {
			fmt.Printf("appendingOracle invocation error: %v\n", err)
		}

		differenceIndex := -1
		for i := 0; i < len(outputCipher) && i < len(outputCipher1); i++ {
			if outputCipher[i] != outputCipher1[i] {
				differenceIndex = i
				break
			}
		}

		if differenceIndex == -1 {
			panic("No difference found")
		}

		// We expect that differenceIndex is on a block boundary, but in edge cases where the first byte(s)
		// of the difference block are coincidentally the same, we need to trim it back to put it on a boundary.
		fmt.Printf("differenceIndex mod blockSizeBytes: %v\n", differenceIndex%blockSizeBytes)
		differenceIndex = differenceIndex - (differenceIndex % blockSizeBytes)
		fmt.Printf("differenceIndex after truncation: %v\n", differenceIndex)

		// Now construct two two-block sized identical buffers that can be used to check
		// for identical output when on the correct boundary.
		// We need two to account for the edge case where the first byte of the target text is the
		// same as the lasst byte of our test buffer.
		identicalBuffer1 := make([]byte, 0)
		identicalBuffer2 := make([]byte, 0)
		for i := 0; i < blockSizeBytes*2; i++ {
			identicalBuffer1 = append(identicalBuffer1, byte(37))
			identicalBuffer2 = append(identicalBuffer2, byte(73))
		}

		// differenceIndex is on the boundary of a block. Figure out how many extra bytes are in the
		// random prefix that create a partial block.
		extraBytes := -1
		for i := 0; i < blockSizeBytes; i++ {
			differenceCipher1, err := appendingOracle(identicalBuffer1)
			if err != nil {
				panic("appendingOracle error")
			}

			differenceCipher2, err := appendingOracle(identicalBuffer2)
			if err != nil {
				panic("appendingOracle error")
			}

			matchFound := true
			for j := 0; j < blockSizeBytes; j++ {
				if differenceCipher1[differenceIndex+j+blockSizeBytes] != differenceCipher1[differenceIndex+j+(2*blockSizeBytes)] || differenceCipher2[differenceIndex+j+blockSizeBytes] != differenceCipher2[differenceIndex+j+(2*blockSizeBytes)] {
					matchFound = false
					break
				}
			}

			if matchFound {
				extraBytes = blockSizeBytes - i
				break
			}

			identicalBuffer1 = append([]byte{byte(i)}, identicalBuffer1...)
			identicalBuffer2 = append([]byte{byte(i)}, identicalBuffer2...)
		}

		if extraBytes == -1 {
			panic("extraBytes value not found")
		}

		randomPrefixSize = differenceIndex + extraBytes
	}

	// Now decrypt the target text
	decipheredPlainTextBytes := make([]byte, 0)
	finished := false

	for finished == false {
		decipheredPlainTextBytes, err = decipherNextByte(decipheredPlainTextBytes, randomPrefixSize, blockSizeBytes, appendingOracle)
		_, err := ch.RemovePadding(decipheredPlainTextBytes)
		if err == nil {
			finished = true
		}
	}

	decipheredPlainTextBytes, err = ch.RemovePadding(decipheredPlainTextBytes)

	decipheredString := string(decipheredPlainTextBytes)
	fmt.Printf("decipheredString: %v\n", decipheredString)
}
