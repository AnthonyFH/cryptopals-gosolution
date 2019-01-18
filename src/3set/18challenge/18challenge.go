package main

import (
	ch "cryptohelpers"
	"encoding/base64"
	"fmt"
)

var key = []byte("YELLOW SUBMARINE")
var nonce = []byte("\x00\x00\x00\x00\x00\x00\x00\x00")
var cipherTextString = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="

func main() {
	cipherTextBytes, err := base64.StdEncoding.DecodeString(cipherTextString)
	if err != nil {
		panic("problem")
	}

	message, err := ch.EncryptDecryptAESCTR(key, nonce, cipherTextBytes)
	if err != nil {
		panic("problem")
	}

	fmt.Printf("The message is: %v", string(message))
}
