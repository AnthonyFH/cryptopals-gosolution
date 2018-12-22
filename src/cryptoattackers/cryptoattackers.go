package cryptoattackers

import (
	"errors"
	"fmt"
)

// DetermineBlockSize will return the blocksize of some encryption func which takes in a []byte.
// The function can potentially do some fixed-size transformation on its input (e.g. append a set number of bytes)
// before encrypting.
func DetermineBlockSize(encryptionFunc func([]byte) ([]byte, error)) (int, error) {
	plainTextBytes := []byte("\x00")

	blockSizeBytes := 0
	hasChanged := false
	changedSize := 0

	cipherTextBytes, err := encryptionFunc(plainTextBytes)
	if err != nil {
		return -1, fmt.Errorf("encryptionFunc invocation error: %v", err)
	}

	// Loop until the output changes size twice
	for blockSizeBytes == 0 {
		plainTextBytes = append(plainTextBytes, byte('\x00'))
		cipherTextBytes1, err := encryptionFunc(plainTextBytes)
		if err != nil {
			return -1, errors.New("encryptionFunc invocation error")
		}

		if len(cipherTextBytes) != len(cipherTextBytes1) {
			if hasChanged {
				blockSizeBytes = len(cipherTextBytes1) - changedSize
			} else {
				hasChanged = true
				changedSize = len(cipherTextBytes1)
			}
		}

		cipherTextBytes = cipherTextBytes1
	}

	return blockSizeBytes, nil
}
