package main

import (
	ch "cryptohelpers"
	"fmt"
)

func main() {
	src := "YELLOW SUBMARINE"
	srcBytes := []byte(src)

	srcBytes, err := ch.AppendPadding(srcBytes, 20)
	if err != nil {
		fmt.Println("Error in appending")
	}

	fmt.Println("srcBytes", srcBytes)
	fmt.Println("srcBytes as string", string(srcBytes))
}
