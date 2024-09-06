package postrunner

import "github.com/OWASP/OFFAT/src/pkg/tgen"

// removes immune endpoints from the api tests slice
func FilterImmuneResults(apiTests *[]*tgen.ApiTest, filterImmune *bool) {
	if !*filterImmune {
		return
	}

	filtered := []*tgen.ApiTest{}
	for _, apiTest := range *apiTests {
		if apiTest.IsDataLeak || apiTest.IsVulnerable {
			filtered = append(filtered, apiTest)
		}
	}
	*apiTests = filtered
}
