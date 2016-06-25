package main

import ("errors"
        "fmt"
        "encoding/hex")

func main() {
    string1 := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736" 
    byte1, _ := hex.DecodeString(string1)

    // XOR the byte slice with every possible byte and save the probability that the result is English.
    tempSlice := make([]byte, len(byte1), len(byte1))
    probSlice := make([]int, 256, 256)
    for j := 0; j < 256; j++ {
        i := byte(j)
        copy(tempSlice, byte1)
        byteXor(tempSlice, i)
        probSlice[i] = probEnglish(tempSlice)
    }
    
    // Find the index of the maximum probability
    max := 0
    index := byte(0)
    for j := 0; j < len(probSlice); j++ {
        i := byte(j)
        if probSlice[i] > max {
            max = probSlice[i]
            index = i
        }
    }

    byteXor(byte1, index)
    fmt.Println(string(byte1))
}

// Takes a  byte slice and in-place xor's it with the given byte.
func byteXor(byteSlice []byte, xorByte byte) error {
    for i :=0; i < len(byteSlice); i++ {
        tempByte := byteSlice[i]
        tempByte ^= xorByte
        byteSlice[i] = tempByte
    }

    return nil
}

// Takes to bytes and xor's them together, returning the result.
func fixedXor(byte1, byte2 []byte) ([]byte, error) {

    result := make([]byte, len(byte1), len(byte1))

    if len(byte1) != len(byte2) {
        return nil, errors.New("Byte lenghts do not match")	
    }

    for i := 0; i < len(byte1); i++ {
        result[i] = byte1[i] ^ byte2[i]
    }
    return result, nil
}

// Returns an integer representing the probability that the ASCII string represented by byteSlice is English.
// This is VERY hacky and does not truly return a probability. Return values should
// only be used to compare to other return values of this function.
func probEnglish(byteSlice []byte) int {
    result := 0
    for i := 0; i < len(byteSlice); i++ {
        
        if byteSlice[i] < byte(' ') {
            result -= 20
        }
        
        if byteSlice[i] > byte('z') {
            result -= 20
        }

        // A list of English characters in order of increasing frequency in typical words
        probString := "zZqQxXjJkKvVbBpPyYgGfFwWmMuUcClLdDrRhHsSnNiIoOaAtTeE"

        for j := 0; j < len(probString); j++ { 
            if byteSlice[i] == probString[j] {
                result += j
            }
        }
    }

    return result
}
