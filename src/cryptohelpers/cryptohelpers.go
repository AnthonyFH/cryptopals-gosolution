package cryptohelpers

import (
	aes "crypto/aes"
	"errors"
)

// DecryptAESECB decrypts encryptedText using AES ECB mode and key. Fails if key
// is not a valid length for AES or if encryptedText is not a multiple of the AES block size (128 bits).
func DecryptAESECB(key []byte, encryptedText []byte) ([]byte, error) {

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSizeBytes := aesBlock.BlockSize()

	if len(encryptedText)%blockSizeBytes != 0 {
		return nil, errors.New("encryptedText not a multiple of block size")
	}

	blockCount := len(encryptedText) / blockSizeBytes

	plaintext := make([]byte, 0, len(encryptedText))

	for i := 0; i < blockCount; i++ {
		decryptedBlock := make([]byte, blockSizeBytes, blockSizeBytes)
		aesBlock.Decrypt(decryptedBlock, encryptedText[i*blockSizeBytes:(i+1)*blockSizeBytes])
		plaintext = append(plaintext, decryptedBlock...)
	}

	// Remove padding (see rfc5652 for padding definition)
	paddingBytes := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-paddingBytes]

	return plaintext, nil
}

// HammingDistanceOfFirstChunks takes the first two chunks of size keysize of bChiper and computes their Hamming Distance
func HammingDistanceOfFirstChunks(bCipher []byte, keySize int) (int, error) {
	if len(bCipher) < 2*keySize {
		return -1, errors.New("bCipher is too short")
	}
	byteSlice1 := bCipher[0:keySize]
	byteSlice2 := bCipher[keySize : 2*keySize]
	byteSlice3 := bCipher[2*keySize : 3*keySize]

	res1, _ := HammingDistance(byteSlice1, byteSlice2)
	res2, _ := HammingDistance(byteSlice2, byteSlice3)

	return res1 + res2, nil
}

// HammingDistance computes the Hamming Distance between two different byte slices of equal length.
func HammingDistance(byteSlice1, byteSlice2 []byte) (int, error) {
	if len(byteSlice1) != len(byteSlice2) {
		return -1, errors.New("Byte lengths do not match")
	}

	result := 0

	for i := 0; i < len(byteSlice1); i++ {
		xorByte := byteSlice1[i] ^ byteSlice2[i]

		for xorByte != 0 {
			result++
			xorByte &= xorByte - 1
		}
	}

	return result, nil
}

// ProbIsEncrypted returns the maximum probability returned from ProbEnglish and also the byte that XOR's to get that probability.
// Return values should only be used to compare with other return values of ProbEnglish.
func ProbIsEncrypted(byteSlice []byte) (int, byte, error) {

	// XOR the byte slice with every possible byte and save the probability that the result is English.
	tempSlice := make([]byte, len(byteSlice), len(byteSlice))
	probSlice := make([]int, 256, 256)
	for j := 0; j < 256; j++ {
		i := byte(j)
		copy(tempSlice, byteSlice)
		ByteXor(tempSlice, i)
		probSlice[i] = ProbEnglish(tempSlice)
	}

	// Find the index of the maximum probability.
	max := 0
	index := byte(0)
	for j := 0; j < len(probSlice); j++ {
		i := byte(j)
		if probSlice[i] > max {
			max = probSlice[i]
			index = i
		}
	}

	return max, index, nil
}

// ByteXor takes a  byte slice and in-place xor's it with the given byte.
func ByteXor(byteSlice []byte, xorByte byte) error {
	for i := 0; i < len(byteSlice); i++ {
		tempByte := byteSlice[i]
		tempByte ^= xorByte
		byteSlice[i] = tempByte
	}

	return nil
}

// FixedXor takes to bytes and xor's them together, returning the result.
func FixedXor(byte1, byte2 []byte) ([]byte, error) {

	result := make([]byte, len(byte1), len(byte1))

	if len(byte1) != len(byte2) {
		return nil, errors.New("Byte lengths do not match")
	}

	for i := 0; i < len(byte1); i++ {
		result[i] = byte1[i] ^ byte2[i]
	}
	return result, nil
}

// ProbEnglish returns an integer representing the probability that the ASCII string represented by byteSlice is English.
// This is VERY hacky and does not truly return a probability. Return values should
// only be used to compare to other return values of this function.
func ProbEnglish(byteSlice []byte) int {
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

// RepeatingKeyXor takes a slice of bytes and in-place XOR's it with the repeated key
func RepeatingKeyXor(inputSlice []byte, key []byte) error {
	j := 0
	for i := 0; i < len(inputSlice); i++ {
		if j == len(key) {
			j = 0
		}

		tempByte := inputSlice[i]
		tempByte = tempByte ^ key[j]
		inputSlice[i] = tempByte

		j++
	}

	return nil
}

// BreakSingleByteXor takes the given string and iterates through all possible single-byte XOR keys
// Returns the single byte key that produces the text most likely to be English
func BreakSingleByteXor(cipher []byte) (byte, error) {

	// XOR the byte slice with every possible byte and save the probability that the result is English.
	tempSlice := make([]byte, len(cipher), len(cipher))
	probSlice := make([]int, 256, 256)
	for j := 0; j < 256; j++ {
		i := byte(j)
		copy(tempSlice, cipher)
		ByteXor(tempSlice, i)
		probSlice[i] = ProbEnglish(tempSlice)
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

	return index, nil
}
