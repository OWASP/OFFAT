package fuzzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/OWASP/OFFAT/src/pkg/fuzzer"
)

// TestGenerateRandomIntInRange tests the GenerateRandomIntInRange function.
func TestGenerateRandomIntInRange(t *testing.T) {
	tests := []struct {
		min, max int
	}{
		{0, 10},
		{10, 20},
		{-10, 10},
		{100, 1000},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("min:%d_max:%d", tt.min, tt.max), func(t *testing.T) {
			num, err := fuzzer.GenerateRandomIntInRange(tt.min, tt.max)
			if err != nil {
				t.Errorf("GenerateRandomIntInRange(%d, %d) returned an error: %v", tt.min, tt.max, err)
			}
			if num < tt.min || num > tt.max {
				t.Errorf("GenerateRandomIntInRange(%d, %d) = %d, expected value between %d and %d", tt.min, tt.max, num, tt.min, tt.max)
			}
		})
	}

	_, err := fuzzer.GenerateRandomIntInRange(10, 0)
	if err == nil {
		t.Error("GenerateRandomIntInRange(10, 0) did not return an error")
	}
}

// TestGenerateRandomChars tests the GenerateRandomChars function.
func TestGenerateRandomChars(t *testing.T) {
	length := 10
	str, err := fuzzer.GenerateRandomChars(length)
	if err != nil {
		t.Errorf("GenerateRandomChars(%d) returned an error: %v", length, err)
	}
	if len(str) != length {
		t.Errorf("GenerateRandomChars(%d) = %s, expected length %d", length, str, length)
	}
}

// TestGenerateRandomCharDigits tests the GenerateRandomCharDigits function.
func TestGenerateRandomCharDigits(t *testing.T) {
	length := 10
	str, err := fuzzer.GenerateRandomCharDigits(length)
	if err != nil {
		t.Errorf("GenerateRandomCharDigits(%d) returned an error: %v", length, err)
	}
	if len(str) != length {
		t.Errorf("GenerateRandomCharDigits(%d) = %s, expected length %d", length, str, length)
	}
}

// TestGenerateRandomString tests the GenerateRandomString function.
func TestGenerateRandomString(t *testing.T) {
	length := 10
	str, err := fuzzer.GenerateRandomString(length)
	if err != nil {
		t.Errorf("GenerateRandomString(%d) returned an error: %v", length, err)
	}
	if len(str) != length {
		t.Errorf("GenerateRandomString(%d) = %s, expected length %d", length, str, length)
	}
}

// TestGeneratePhoneNumber tests the GeneratePhoneNumber function.
func TestGeneratePhoneNumber(t *testing.T) {
	phone, err := fuzzer.GeneratePhoneNumber()
	if err != nil {
		t.Errorf("GeneratePhoneNumber() returned an error: %v", err)
	}
	if len(phone) != 10 {
		t.Errorf("GeneratePhoneNumber() = %s, expected length 10", phone)
	}
	if !strings.HasPrefix(phone, "72") {
		t.Errorf("GeneratePhoneNumber() = %s, expected prefix 72", phone)
	}
}
