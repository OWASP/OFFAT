package postrunner

import (
	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/tgen"
	"github.com/OWASP/OFFAT/src/pkg/utils"
)

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

// marks api test vulnerable or immune based on the API test VulnerableResponseCodes/ImmuneResponseCodes
func UpdateStatusCodeBasedResult(apiTests *[]*tgen.ApiTest) {
	for _, apiTest := range *apiTests {
		if apiTest.Response.Error != nil {
			continue
		}

		if len(apiTest.ImmuneResponseCodes) > 0 {
			if !utils.SearchInSlice(apiTest.ImmuneResponseCodes, apiTest.Response.Response.StatusCode) {
				apiTest.IsVulnerable = true
			}
		} else if len(apiTest.VulnerableResponseCodes) > 0 {
			if utils.SearchInSlice(apiTest.VulnerableResponseCodes, apiTest.Response.Response.StatusCode) {
				apiTest.IsVulnerable = true
			}
		}
	}
}
