package main

import (
	ch "cryptohelpers"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	filename := "4.txt"

	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file", filename)
		return
	}

	ciphers, err := ioutil.ReadAll(file)

	cipherList := strings.Split(string(ciphers), "\n")
	byteList := make([][]byte, len(cipherList), len(cipherList))

	for i := 0; i < len(cipherList); i++ {
		byteList[i], err = hex.DecodeString(cipherList[i])
		if err != nil {
			fmt.Println("Error decoding hex string")
			return
		}
	}

	probList := make([]int, len(byteList), len(byteList))
	probByteList := make([]byte, len(byteList), len(byteList))

	for i := 0; i < len(cipherList); i++ {
		probList[i], probByteList[i], _ = ch.ProbIsEncrypted(byteList[i])
	}

	max := 0
	maxIndex := 0
	maxByte := byte(0)
	for i := 0; i < len(probList); i++ {
		if probList[i] > max {
			maxIndex = i
			max = probList[i]
			maxByte = probByteList[i]
		}
	}

	ch.ByteXor(byteList[maxIndex], maxByte)

	fmt.Println("The string that was encrypted was string", maxIndex)
	fmt.Println("The message was:")
	fmt.Println(string(byteList[maxIndex]))
}
