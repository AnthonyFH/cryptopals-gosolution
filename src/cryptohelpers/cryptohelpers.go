package cryptohelpers

import (
	aes "crypto/aes"
	"errors"
	"fmt"
	"math/rand"
)

// EncryptAESCBC encrypts messages using AES with the given key using CBC
// mode with the given initialization vector (iv)
func EncryptAESCBC(key []byte, iv []byte, message []byte) ([]byte, error) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSizeBytes := aesBlock.BlockSize()

	message, err = AppendPadding(message, blockSizeBytes)
	if err != nil {
		return nil, err
	}

	encryptedMessage := make([]byte, 0, len(message))

	if len(iv) != blockSizeBytes {
		return nil, errors.New("Initialization vector has incorrect length")
	}

	previousBlockResult := iv
	for i := 0; i < len(message); i += blockSizeBytes {
		blockInput, err := FixedXor(previousBlockResult, message[i:i+blockSizeBytes])
		if err != nil {
			return nil, err
		}

		blockOutput := make([]byte, blockSizeBytes)

		aesBlock.Encrypt(blockOutput, blockInput)

		previousBlockResult = blockOutput

		encryptedMessage = append(encryptedMessage, blockOutput...)
	}

	return encryptedMessage, nil
}

// DecryptAESCBC decrypts messages using AES with the given key using CBC
// mode with the given initialization vector (iv).
func DecryptAESCBC(key []byte, iv []byte, encryptedMessage []byte) ([]byte, error) {
	return decryptAESCBCInternal(key, iv, encryptedMessage, true)
}

// DecryptAESCBCLeavePadding decrypts messages using AES with the given key using CBC
// mode with the given initialization vector (iv). It does not strip any padding from
// the raw unencrypted plaintext.
func DecryptAESCBCLeavePadding(key []byte, iv []byte, encryptedMessage []byte) ([]byte, error) {
	return decryptAESCBCInternal(key, iv, encryptedMessage, false)
}

// decryptAESCBCInternal decrypts messages using AES with the given key using CBC
// mode with the given initialization vector (iv). It optionally strips the padding.
func decryptAESCBCInternal(key []byte, iv []byte, encryptedMessage []byte, doRemovePadding bool) ([]byte, error) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSizeBytes := aesBlock.BlockSize()

	decryptedMessage := make([]byte, 0, len(encryptedMessage))

	if len(iv) != blockSizeBytes {
		return nil, errors.New("Initialization vector has incorrect length")
	}

	if len(encryptedMessage)%blockSizeBytes != 0 {
		return nil, errors.New("len(encryptedMessage) is ")
	}

	previousCipher := iv
	for i := 0; i < len(encryptedMessage); i += blockSizeBytes {
		blockInput := encryptedMessage[i : i+blockSizeBytes]

		blockOutput := make([]byte, blockSizeBytes)

		xorValue := previousCipher
		previousCipher = blockInput

		aesBlock.Decrypt(blockOutput, blockInput)

		blockOutput, err = FixedXor(xorValue, blockOutput)
		if err != nil {
			return nil, err
		}

		decryptedMessage = append(decryptedMessage, blockOutput...)
	}

	if doRemovePadding {
		decryptedMessage, err = RemovePadding(decryptedMessage)
		if err != nil {
			return nil, err
		}
	}

	return decryptedMessage, nil
}

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

	plainText := make([]byte, 0, len(encryptedText))

	for i := 0; i < blockCount; i++ {
		decryptedBlock := make([]byte, blockSizeBytes, blockSizeBytes)
		aesBlock.Decrypt(decryptedBlock, encryptedText[i*blockSizeBytes:(i+1)*blockSizeBytes])
		plainText = append(plainText, decryptedBlock...)
	}

	plainText, err = RemovePadding(plainText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// EncryptAESECB encrypts message using AES ECB mode and key. Fails if key
// is not a valid length for AES.
func EncryptAESECB(key []byte, message []byte) ([]byte, error) {

	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSizeBytes := aesBlock.BlockSize()

	message, err = AppendPadding(message, blockSizeBytes)

	blockCount := len(message) / blockSizeBytes

	cipher := make([]byte, 0, len(message))

	for i := 0; i < blockCount; i++ {
		encryptedBlock := make([]byte, blockSizeBytes, blockSizeBytes)
		aesBlock.Encrypt(encryptedBlock, message[i*blockSizeBytes:(i+1)*blockSizeBytes])
		cipher = append(cipher, encryptedBlock...)
	}

	return cipher, nil
}

// AppendPadding takes a byte slice and a block size returns a byte slice with
// appended padding so that its length is an even multiple of the block size
func AppendPadding(message []byte, blockSize int) ([]byte, error) {
	remainder := len(message) % blockSize
	paddingLength := blockSize - remainder
	paddingValue := byte(paddingLength)
	for i := 0; i < paddingLength; i++ {
		message = append(message, paddingValue)
	}

	return message, nil
}

// RemovePadding takes a mesage and returns that message without
// padding as defined in RFC 2315
func RemovePadding(message []byte) ([]byte, error) {
	paddingBytes := int(message[len(message)-1])

	if paddingBytes == 0 {
		return nil, errors.New("Inavlid padding")
	}

	for i := 1; i <= paddingBytes; i++ {
		if i == len(message) || message[len(message)-i] != byte(paddingBytes) {
			return nil, errors.New("Invalid padding")
		}
	}

	message = message[:len(message)-paddingBytes]

	return message, nil
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

// FixedXor takes two byte slices and xor's them together, returning the result.
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

// CBCECBEncryptionOracle encrypts the input plainText using either CBC or ECB (selected at random)
// with a random key (and IV in case of ECB). Appends and prepends 5-10 random bytes.
func CBCECBEncryptionOracle(plainText []byte) ([]byte, error) {
	prependByteCount := (rand.Int() % 5) + 5
	prependBytes := make([]byte, prependByteCount)
	rand.Read(prependBytes)

	appendByteCount := (rand.Int() % 5) + 5
	appendBytes := make([]byte, appendByteCount)
	rand.Read(appendBytes)

	keyByteCount := 16
	key := make([]byte, keyByteCount)
	rand.Read(key)

	ivByteCount := aes.BlockSize
	iv := make([]byte, ivByteCount)
	rand.Read(iv)

	plainTextNew := append(prependBytes, plainText...)
	plainTextNew = append(plainTextNew, appendBytes...)

	randInt := rand.Int() % 2

	if randInt == 0 {
		fmt.Println("Oracle: CBC")
		byteSlice, err := EncryptAESCBC(key, iv, plainTextNew)
		return byteSlice, err
	} else {
		fmt.Println("Oracle: ECB")
		byteSlice, err := EncryptAESECB(key, plainTextNew)
		return byteSlice, err
	}
}

// IsECB takes an encryption function and outputs
// whether or not the function is using ECB
func IsECB(encryptionFunc func([]byte) ([]byte, error)) (bool, error) {

	plainText := []byte("\x00")

	// Decide how many bytes we need to input to the function to be sure the middle is what we should look at.
	lengthOfInput := 1000
	for i := 0; i < lengthOfInput; i++ {
		plainText = append(plainText, '\x00')
	}

	cipherText, err := encryptionFunc(plainText)
	if err != nil {
		return false, errors.New("Error with encryption oracle")
	}

	// Default to guessing ECB. If the two blocks in the middle do not match, this is not ECB.
	isECB := true
	for i := 0; i < aes.BlockSize; i++ {
		index1 := (len(cipherText) / 2) + i
		index2 := (len(cipherText) / 2) + i + aes.BlockSize
		if cipherText[index1] != cipherText[index2] {
			isECB = false
			break
		}
	}

	return isECB, nil
}
