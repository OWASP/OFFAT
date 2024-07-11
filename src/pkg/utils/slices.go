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
