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

	filename := "10.txt"

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

	iv := []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	plaintextBytes, err := ch.DecryptAESCBC(decryptionKey, iv, cipherBytes)
	if err != nil {
		fmt.Println("Error decrypting", err)
		return
	}

	cipherBytes, err = ch.EncryptAESCBC(decryptionKey, iv, plaintextBytes)
	if err != nil {
		fmt.Println("Error encrypting", err)
		return
	}

	plaintextBytes, err = ch.DecryptAESCBC(decryptionKey, iv, cipherBytes)
	if err != nil {
		fmt.Println("Error decrypting", err)
		return
	}
	fmt.Print(string(plaintextBytes))
}
