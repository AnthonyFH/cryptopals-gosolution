package main

import (
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
		fmt.Printf("Character: %v\n", string(profile[i]))
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

func profileFor(email: string) {
	// TODO fill in profilFor and add documentation
}

func main() {
	myMap, _ := parseProfile("abc=def&foo=bar")

	fmt.Printf("map: %v\n", myMap)
}
