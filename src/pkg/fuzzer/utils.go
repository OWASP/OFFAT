package fuzzer

import "strings"

// FuzzStringType generates a fuzzed string based on the variable name.
func FuzzStringType(varName string) (string, error) {
	varNameLower := strings.ToLower(varName)
	switch {
	case strings.Contains(varNameLower, "email"):
		varValue, err := GenerateRandomCharDigits(6)
		if err != nil {
			return "", err
		}
		return varValue + "@example.com", nil
	case strings.Contains(varNameLower, "password"):
		return GenerateRandomString(15)
	case strings.Contains(varNameLower, "phone"):
		return GeneratePhoneNumber()
	case strings.Contains(varNameLower, "name"):
		return GenerateRandomChars(7)
	case strings.Contains(varNameLower, "username"):
		return GenerateRandomCharDigits(6)
	default:
		return GenerateRandomString(10)
	}
}
