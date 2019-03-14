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

	filename := "19challengeplaintextlist.txt"

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

	maxCipherSize := 0

	for i := 0; i < len(cipherList); i++ {
		if (len(cipherList[i])) > maxCipherSize {
			maxCipherSize = len(cipherList[i])
		}
	}

	// The axis of the matrix are in order:
	// - Character index
	// - Byte possibility
	// Note that some places will be nil based on the length
	// of a particular cipher.
	probabilityMatrix := make([][]int, maxCipherSize)

	for i := 0; i < maxCipherSize; i++ {
		probabilityMatrix[i] = make([]int, 256)
		for j := 0; j < 256; j++ {
			probabilityMatrix[i][j] = 0
		}
	}

	// Iterate through every cipher, then every byte, then every keyStreamByte possibility
	// and calculate the probability that the resulting byte is an English character.
	for i := 0; i < len(cipherList); i++ {
		for j := 0; j < len(cipherList[i]); j++ {
			for k := 0; k < 256; k++ {
				singleByteByteSlice1 := make([]byte, 1)
				singleByteByteSlice1[0] = byte(k)
				singleByteByteSlice2 := make([]byte, 1)
				singleByteByteSlice2[0] = byte(cipherList[i][j : j+1][0])
				singleByteByteSlice3, err := ch.FixedXor(singleByteByteSlice1, singleByteByteSlice2)
				if err != nil {
					panic("problem")
				}
				probabilityMatrix[j][k] += ch.ProbEnglish(singleByteByteSlice3)
			}
		}
	}

	// Now for each character find the keyStreamyByte with the highest probability
	probableKeyStream := make([]byte, maxCipherSize)

	for i := 0; i < maxCipherSize; i++ {
		maxIndex := 0
		maxIndexValue := 0

		for j := 0; j < 256; j++ {
			if probabilityMatrix[i][j] > maxIndexValue {
				maxIndex = j
				maxIndexValue = probabilityMatrix[i][j]
			}
		}

		probableKeyStream[i] = byte(maxIndex)
	}

	// Now get all the plaintexts that the probablyeKeyStream will produce
	probablePlaintextList := make([][]byte, len(cipherList))

	for i := 0; i < len(cipherList); i++ {
		probablePlaintextList[i], err = ch.FixedXor(cipherList[i], probableKeyStream[0:len(cipherList[i])])
		if err != nil {
			panic("problem")
		}
	}

	for i := 0; i < len(probablePlaintextList); i++ {
		print(string(probablePlaintextList[i]))
		print("\n")
	}

	// TODO this is mostly complete, but the later letters don't have enough data so they are slightly off.
	// The plaintext is "Easter, 1916" by William Butler Yeats so I could fix it manually here, but I'm lazy.
}
