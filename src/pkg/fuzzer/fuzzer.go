package fuzzer

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// GenerateRandomIntInRange generates a random integer value between min and max (inclusive).
func GenerateRandomIntInRange(min, max int) (int, error) {
	if min > max {
		return 0, fmt.Errorf("min should be less than or equal to max")
	}
	rangeSize := big.NewInt(int64(max - min + 1))
	n, err := rand.Int(rand.Reader, rangeSize)
	if err != nil {
		return 0, err
	}
	return int(n.Int64()) + min, nil
}

// GenerateRandomChars generates a random string of given length containing characters only.
func GenerateRandomChars(length int) (string, error) {
	characters := LowerCaseCharset + UpperCaseCharset
	return generateRandomStringFromCharset(length, characters)
}

// GenerateRandomCharDigits generates a random string of given length containing characters and digits only.
func GenerateRandomCharDigits(length int) (string, error) {
	characters := LowerCaseCharset + UpperCaseCharset + DigitsCharset
	return generateRandomStringFromCharset(length, characters)
}

// GenerateRandomString generates a random string of given length.
func GenerateRandomString(length int) (string, error) {
	characters := LowerCaseCharset + UpperCaseCharset + DigitsCharset + SpecialCharset
	return generateRandomStringFromCharset(length, characters)
}

func GenerateRandomBoolean() bool {
	value, err := GenerateRandomIntInRange(0, 1)
	if err != nil {
		return false
	}

	return value == 1
}

// Helper function to generate a random string from a given character set.
func generateRandomStringFromCharset(length int, charset string) (string, error) {
	var sb strings.Builder
	for i := 0; i < length; i++ {
		index, err := GenerateRandomIntInRange(0, len(charset)-1)
		if err != nil {
			return "", err
		}
		sb.WriteByte(charset[index])
	}
	return sb.String(), nil
}

// GeneratePhoneNumber generates a random 10-digit phone number starting with 72.
func GeneratePhoneNumber() (string, error) {
	digits := DigitsCharset
	var sb strings.Builder
	sb.WriteString("72")
	for i := 0; i < 8; i++ {
		index, err := GenerateRandomIntInRange(0, len(digits)-1)
		if err != nil {
			return "", err
		}
		sb.WriteByte(digits[index])
	}
	return sb.String(), nil
}
