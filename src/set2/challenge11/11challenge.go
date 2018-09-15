package main

import (
	ch "cryptohelpers"
	"fmt"
)

func main() {
	// Go through 50 times and make sure we guess correctly ever time.
	for i := 0; i < 50; i++ {
		fmt.Println("========START==========")
		isECB, err := ch.IsECB(ch.CBCECBEncryptionOracle)
		if (err == nil) && isECB {
			fmt.Println("Guess: ECB")
		} else if err == nil {
			fmt.Println("Guess: CBC")
		} else {
			fmt.Println(err)
		}
		fmt.Println("==========END==========")
	}
}
