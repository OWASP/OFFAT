package tgen

type TestSchema struct {
	TestName     string
	IsVulnerable bool
	IsDataLeak   bool
	Request      interface{}
	Response     interface{}
}
