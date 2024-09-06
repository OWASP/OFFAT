package postrunner

import (
	"regexp"

	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/tgen"
	"github.com/OWASP/OFFAT/src/pkg/utils"
	"github.com/rs/zerolog/log"
)

// marks api test vulnerable or immune based on the API test VulnerableResponseCodes/ImmuneResponseCodes
func UpdateStatusCodeBasedResult(apiTests *[]*tgen.ApiTest) {
	for _, apiTest := range *apiTests {
		if apiTest.Response.Error != nil {
			continue
		}

		if len(apiTest.ImmuneResponseCodes) > 0 {
			apiTest.IsVulnerable = !utils.SearchInSlice(apiTest.ImmuneResponseCodes, apiTest.Response.Response.StatusCode)
		} else if len(apiTest.VulnerableResponseCodes) > 0 {
			apiTest.IsVulnerable = utils.SearchInSlice(apiTest.VulnerableResponseCodes, apiTest.Response.Response.StatusCode)
		} else if len(apiTest.MatchRegex) > 0 {
			isVuln, err := regexp.Match(apiTest.MatchRegex, apiTest.Response.Response.Body)
			if err != nil {
				log.Error().Stack().Err(err).Msg("failed to validate match regex against response body")
			}
			apiTest.IsVulnerable = isVuln
		}
	}
}
