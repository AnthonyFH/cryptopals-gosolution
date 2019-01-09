package main

import (
	ch "cryptohelpers"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {

	decryptionKey := []byte("YELLOW SUBMARINE")

	filename := "7.txt"

	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file", filename)
		return
	}

	cipher, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println("Error reading file", filename)
		return
	}

	cipherString := string(cipher)

	cipherString = strings.Replace(cipherString, "\n", "", -1)

	cipherBytes, err := base64.StdEncoding.DecodeString(cipherString)
	if err != nil {
		fmt.Println("Error decoding cipher")
		return
	}

	plaintextBytes, err := ch.DecryptAESECB(decryptionKey, cipherBytes)
	if err != nil {
		fmt.Println("Error decrypting", err)
		return
	}

	fmt.Print(string(plaintextBytes))
}
