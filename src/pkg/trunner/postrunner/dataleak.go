package postrunner

import (
	"sync"

	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/tgen"
	"github.com/OWASP/OFFAT/src/pkg/utils"
	"github.com/dlclark/regexp2"
)

// Note: DataLeakPattern, DataLeakPatterns, and DataLeakPatternMatch struct are stored
// in tgen/structs.go to avoid circular imports

// Post process test for detecting sensitive data leak in API test
// response body as per provided data leak patterns.
// It can be cpu intensive, so it's preffered to only include patterns for which
// data is available in the API
func UpdateDataLeakResult(apiTests *[]*tgen.ApiTest, patterns tgen.DataLeakPatterns) {
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, apiTest := range *apiTests {
		if apiTest.Response.Error != nil {
			continue
		}

		wg.Add(1)
		go func(apiTest *tgen.ApiTest) {
			mu.Lock()

			defer wg.Done()
			defer mu.Unlock()

			dataLeakMatches := IsDataLeak(apiTest.Response.Response.Body, patterns)

			if len(dataLeakMatches) > 0 {

				apiTest.IsDataLeak = true
				apiTest.DataLeakMatches = dataLeakMatches
			}
		}(apiTest)
	}

	wg.Wait()
}

// checks for data leak in target as per provided DataLeakPatterns struct
func IsDataLeak(target []byte, patterns tgen.DataLeakPatterns) []tgen.DataLeakPatternMatch {
	var matches []tgen.DataLeakPatternMatch
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Match the response body against each pattern concurrently
	for _, pattern := range patterns.Patterns {
		if pattern.Regex == "" {
			continue
		}

		wg.Add(1)
		go func(pattern tgen.DataLeakPattern) {
			mu.Lock()

			defer wg.Done()
			defer mu.Unlock()

			re := regexp2.MustCompile(pattern.Regex, regexp2.RE2)
			strMatches := utils.FindAllString(re, string(target))
			// log.Info().Msgf("%v %v", pattern.Regex, matches)

			if len(strMatches) > 0 {
				matches = append(matches, tgen.DataLeakPatternMatch{
					DataLeakPattern: pattern,
					Matches:         strMatches,
				})
			}

		}(pattern)
	}

	wg.Wait()

	return matches
}
