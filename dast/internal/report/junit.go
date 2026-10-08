package report

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/dmdhrumilmistry/offat-ai/dast/internal/detect"
)

// WriteJUnit emits a JUnit XML report so CI systems (GitHub Actions,
// GitLab, Jenkins) can ingest DAST findings as test results. Each finding
// becomes a <testcase>; any finding the triager did not rule out as a
// false positive is rendered as a <failure>, so a clean scan shows green.
func WriteJUnit(w io.Writer, r *Report) error {
	suite := junitSuite{
		Name:  toolName,
		Tests: len(r.Findings),
		Time:  "0",
	}
	for _, f := range r.Findings {
		tc := junitCase{
			Name:      caseName(f),
			ClassName: f.Class,
			Time:      "0",
		}
		if isActionable(f) {
			suite.Failures++
			tc.Failure = &junitFailure{
				Type:    f.Severity,
				Message: junitMessage(f),
				Body:    junitBody(f),
			}
		}
		suite.Cases = append(suite.Cases, tc)
	}
	doc := junitSuites{
		Tests:    suite.Tests,
		Failures: suite.Failures,
		Suites:   []junitSuite{suite},
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// isActionable reports whether a finding should count against a CI gate: it
// is a real signal unless the triager explicitly marked it a false positive.
func isActionable(f *detect.Finding) bool {
	return verdictOf(f) != "false_positive"
}

func caseName(f *detect.Finding) string {
	name := f.Title
	if f.Endpoint != "" {
		name += " [" + f.Endpoint + "]"
	}
	if f.Param != "" {
		name += " (" + f.Param + ")"
	}
	return name
}

func junitMessage(f *detect.Finding) string {
	m := titleCase(f.Severity) + " " + f.Class
	if v := verdictOf(f); v != "" {
		m += " — " + v
	}
	return m
}

func junitBody(f *detect.Finding) string {
	b := fmt.Sprintf("%s\nendpoint: %s\ncwe: %s owasp: %s\n", f.Description, f.Endpoint, f.CWE, f.OWASP)
	if f.Payload != "" {
		b += "payload: " + oneLine(f.Payload) + "\n"
	}
	b += fmt.Sprintf("evidence: %s -> status %d\n", f.Evidence.RequestMethod, f.Evidence.StatusCode)
	if f.Triage != nil && f.Triage.Remediation != "" {
		b += "remediation: " + f.Triage.Remediation + "\n"
	}
	return b
}

// ---- JUnit types ----

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Time     string      `xml:"time,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}
