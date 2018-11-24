package main

import (
	"crypto/rand"
	ca "cryptoattackers"
	ch "cryptohelpers"
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

	profile["email"] = email
	profile["id"] = "10"
	profile["role"] = "user"

	var resultBuilder strings.Builder
	resultBuilder.Reset()

	for property, value := range profile {
		resultBuilder.WriteString(property)
		resultBuilder.WriteString("=")
		resultBuilder.WriteString(value)
		resultBuilder.WriteString("&")
	}

	result := resultBuilder.String()

	result = strings.TrimSuffix(result, "&")

	return result, nil
}

func getEncryptedProfile(profile string) ([]byte, error) {
	// Generate a random key if needed
	if superSecretKey == nil {
		fmt.Println("GENERATED KEY")
		keyByteCount := 16
		superSecretKey = make([]byte, keyByteCount)
		rand.Read(superSecretKey)
	}

	cipher, err := ch.EncryptAESECB(superSecretKey, []byte(profile))
	if err != nil {
		panic(err)
	}

	return cipher, nil
}

func main() {
	// TODO undefined: err (say what?!)
	blockSizeBytes, err := ca.DetermineBlockSize(func(input []byte) ([]byte, err) { return getEncryptedProfile(string(input)) })
	if err != nil {
		panic("couldn't determine block size")
	}

	fmt.Printf("blockSizeBytes: %v\n", blockSizeBytes)

	cipher, err := getEncryptedProfile("testemail@mydomain.com")
	if err != nil {
		panic("getEncryptedProfile error")
	}
}
