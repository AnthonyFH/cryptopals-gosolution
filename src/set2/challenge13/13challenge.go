package main

import (
	"crypto/rand"
	ca "cryptoattackers"
	ch "cryptohelpers"
	"errors"
	"fmt"
	"strings"
)

var superSecretKey []byte

// parseProfile takes in a string reprsenting a profile
// encoded like so: prop1=foo&prop2=bar&... and
// returns a map from properties to values
func parseProfile(profile string) (map[string]string, error) {

	var propBuilder, valBuilder strings.Builder
	preallocateLength := 10
	propBuilder.Grow(preallocateLength)
	valBuilder.Grow(preallocateLength)

	result := make(map[string]string)

	readingProp := true // are we currently reading a property or a value?
	for i := 0; i < len(profile); i++ {
		if readingProp {
			switch profile[i] {
			case '=':
				readingProp = false // switch to reading a value
			case '&':
				panic("Invalid character")
			default:
				propBuilder.WriteByte(profile[i])
			}
		} else {
			switch profile[i] {
			case '=':
				panic("Invalid character")
			case '&':
				readingProp = true // switch to reading a property
				result[propBuilder.String()] = valBuilder.String()
				propBuilder.Reset()
				valBuilder.Reset()
			default:
				valBuilder.WriteByte(profile[i])
			}
		}
	}

	if readingProp != false {
		panic("Expect parsing to finish when reading a property")
	}

	result[propBuilder.String()] = valBuilder.String()
	propBuilder.Reset()
	valBuilder.Reset()

	return result, nil
}

// profileFor takes a users email and returns
// its profile encoded as email=<email>&prop2=bar&...
func profileFor(email string) (string, error) {
	profile := make(map[string]string)

	if strings.Contains(email, "&") || strings.Contains(email, "=") {
		return "", errors.New("Invalid character")
	}

	profile["email"] = email
	profile["uid"] = "10"
	profile["role"] = "user"

	var resultBuilder strings.Builder
	resultBuilder.Reset()

	// Properties are not iterated through in a deterministic order we need to hardcode the order
	// email
	for i := 0; i < 3; i++ {
		var property string
		switch i {
		case 0:
			property = "email"
		case 1:
			property = "uid"
		case 2:
			property = "role"
		}
		resultBuilder.WriteString(property)
		resultBuilder.WriteString("=")
		resultBuilder.WriteString(profile[property])
		resultBuilder.WriteString("&")
	}

	result := resultBuilder.String()

	result = strings.TrimSuffix(result, "&")

	return result, nil
}

func getEncryptedProfile(email string) ([]byte, error) {
	// Generate a random key if needed
	if superSecretKey == nil {
		fmt.Println("GENERATED KEY")
		keyByteCount := 16
		superSecretKey = make([]byte, keyByteCount)
		rand.Read(superSecretKey)
	}

	profile, err := profileFor(email)
	if err != nil {
		panic(err)
	}

	cipher, err := ch.EncryptAESECB(superSecretKey, []byte(profile))
	if err != nil {
		panic(err)
	}

	return cipher, nil
}

func getDecryptedProfile(cipher []byte) (map[string]string, error) {
	// The key should already be generated
	if superSecretKey == nil {
		return nil, errors.New("No decryption key")
	}

	profileBytes, err := ch.DecryptAESECB(superSecretKey, cipher)
	if err != nil {
		panic(err)
	}

	profile, err := parseProfile(string(profileBytes))
	if err != nil {
		panic(err)
	}

	return profile, nil
}

func main() {
	blockSizeBytes, err := ca.DetermineBlockSize(func(input []byte) ([]byte, error) { return getEncryptedProfile(string(input)) })
	if err != nil {
		panic("couldn't determine block size")
	}

	fmt.Printf("blockSizeBytes: %v\n", blockSizeBytes)

	// We know that the string we pass will get the following added before: "email="
	// And the following added after: "&uid=10&role=user"
	// We want some cipher that has "user" by itself in a block so that we can
	// paste on top of that.
	prependSize := 6 // length of "email="
	appendSize := 13 // length of "&uid=10&role="
	//userSize := 4    // length of "user"

	pasteEmailSize := (blockSizeBytes - prependSize - appendSize) % blockSizeBytes // the email we'll use for the final "attack" profile
	if pasteEmailSize < 0 {
		pasteEmailSize += blockSizeBytes
	}

	copyPrependSize := (blockSizeBytes - prependSize) % blockSizeBytes // the begining email size we'll use to get our "admin" + padding block
	if copyPrependSize < 0 {
		copyPrependSize += blockSizeBytes
	}

	fmt.Printf("pasteEmailSize %v\n", pasteEmailSize)
	fmt.Printf("copyPrependSize %v\n", copyPrependSize)

	// Construct the attack email
	var attackBuilder strings.Builder
	attackSuffix := "@b.com"
	if pasteEmailSize < len(attackSuffix)+1 {
		panic("EmailSizeIsTooSmall")
	}
	for i := 0; i < pasteEmailSize-len(attackSuffix); i++ {
		attackBuilder.WriteString("a")
	}
	attackBuilder.WriteString(attackSuffix)
	fmt.Printf("Length of attackString: %v\n", len(attackBuilder.String()))

	// The last block should contain "user" + padding
	// We'll paste in "admin" + padding later
	cipher, err := getEncryptedProfile(attackBuilder.String())
	if err != nil {
		panic("getEncryptedProfile error")
	}

	fmt.Printf("cipher: %v\n", cipher)

	profile, err := getDecryptedProfile(cipher)

	fmt.Printf("profile: %v\n", profile)

	// Construct the "email" to get our admin block that will be copied
	var copyBuilder strings.Builder
	for i := 0; i < copyPrependSize; i++ {
		copyBuilder.WriteString("a")
	}
	adminString := "admin"
	copyBuilder.WriteString(adminString)
	for i := 0; i < blockSizeBytes-len(adminString); i++ {
		copyBuilder.WriteString(string(byte(blockSizeBytes - len(adminString))))
	}
	fmt.Printf("Length of copyString: %v\n", len(copyBuilder.String()))

	copyCipher, err := getEncryptedProfile(copyBuilder.String())
	if err != nil {
		panic("getEncryptedProfile error")
	}

	fmt.Printf("copyCipher: %v\n", copyCipher)

	copyProfile, err := getDecryptedProfile(copyCipher)

	fmt.Printf("copyProfile: %v\n", copyProfile)

	// Copy the bytes over
	for i := 0; i < blockSizeBytes; i++ {
		cipher[len(cipher)-blockSizeBytes+i] = copyCipher[blockSizeBytes+i]
	}

	finalProfile, err := getDecryptedProfile(cipher)

	fmt.Printf("finalProfile: %v\n", finalProfile)

}
