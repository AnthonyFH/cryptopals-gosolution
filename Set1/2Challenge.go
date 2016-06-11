package main

import ("errors"
	"fmt"
	"encoding/hex")

func main() {
	string1 := "1c0111001f010100061a024b53535009181c"
	string2 := "686974207468652062756c6c277320657965"
	byte1, _ := hex.DecodeString(string1)
	byte2, _ := hex.DecodeString(string2)
	result, _ := fixedXor(byte1, byte2)
	fmt.Printf("%X\n", result)
}

func fixedXor(byte1, byte2 []byte) ([]byte, error) {
	
	result := make([]byte, len(byte1), len(byte1))
	
	if len(byte1) != len(byte2) {
		return nil, errors.New("Byte lenghts do not match")	
	}

	for i:= 0; i < len(byte1); i++ {
		result[i] = byte1[i] ^ byte2[i]
	}
	return result, nil
}
