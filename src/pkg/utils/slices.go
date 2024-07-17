package utils

// Function to search for a string in a slice of strings
func SearchStringInSlice(strings []string, search string) bool {
	for _, str := range strings {
		if str == search {
			return true
		}
	}
	return false
}

func RemoveElement[T comparable](slice []T, element T) []T {
	for i, v := range slice {
		if v == element {
			slice = append(slice[:i], slice[i+1:]...)
			break
		}
	}
	return slice
}

func SearchInSlice[T comparable](slice []T, element T) bool {
	for _, v := range slice {
		if v == element {
			return true
		}
	}

	return false
}
