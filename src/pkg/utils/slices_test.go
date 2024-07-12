package utils_test

import (
	"testing"

	"github.com/OWASP/OFFAT/src/pkg/utils"
)

func TestSearchStringInSlice(t *testing.T) {
	slice := []string{"this", "is", "a", "test"}
	target1 := "test" // present in slice
	target2 := "naah" // absent in slice

	t.Run("Target present in slice", func(t *testing.T) {
		if !utils.SearchStringInSlice(slice, target1) {
			t.Fatalf("target %s is present in slice, but func SearchStringInSlice returned False", target1)
		}
	})

	t.Run("Target absent in slice", func(t *testing.T) {
		if utils.SearchStringInSlice(slice, target2) {
			t.Fatalf("target %s is not present in slice, but func SearchStringInSlice returned True", target2)
		}
	})

}
