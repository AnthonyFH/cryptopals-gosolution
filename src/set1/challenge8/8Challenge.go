package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
)

func main() {

	filename := "8.txt"

	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file", filename)
		return
	}

	fileContents, err := ioutil.ReadAll(file)
	if err != nil {
		fmt.Println("Error reading file", filename)
		return
	}

	fileContentsString := string(fileContents)

	cipherStringList := strings.Split(fileContentsString, "\n")
	cipherBytesList := make([][]byte, len(cipherStringList))

	for i := 0; i < len(cipherStringList); i++ {
		cipherBytesList[i], err = base64.StdEncoding.DecodeString(cipherStringList[i])
		if err != nil {
			fmt.Println("Error decoding cipher")
			return
		}
	}

	// For each cipher, try to find a match between two 16-byte chunks.
	for i := 0; i < len(cipherBytesList); i++ {
		// Cheating on error handling here since we only have one input file
		for j := 0; j < len(cipherBytesList[i])/16; j++ {
			for k := 0; k < len(cipherBytesList[i])/16; k++ {
				if j != k {
					jSlice := cipherBytesList[i][j*16 : (j+1)*16]
					kSlice := cipherBytesList[i][k*16 : (k+1)*16]
					if reflect.DeepEqual(jSlice, kSlice) {
						fmt.Println("Equal!", jSlice, kSlice)
						fmt.Println("i: ", i)
					}
				}
			}
		}
	}
}
