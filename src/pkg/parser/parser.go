package parser

import "fmt"

type Param struct {
	Name        string
	In          string
	Required    bool
	Type        []string
	Value       interface{}
	ContentType string
}

func (p *Param) String() string {
	return fmt.Sprintf("%T{ Name:%v Value:%v In:%v Required:%v }", p, p.Name, p.Value, p.In, p.Value)
}

// DocHttpParams holds useful information about payloads and security requirements from the docs
type DocHttpParams struct {
	// Request Information
	HttpMethod string
	Path       string

	// Security Requirements
	Security []map[string][]string

	// Request Params
	BodyParams   []Param
	CookieParams []Param
	HeaderParams []Param
	PathParams   []Param
	QueryParams  []Param

	// Response Params
	ResponseParams []Param
}

func (d *DocHttpParams) String() string {
	return fmt.Sprintf("%T{ HttpMethod:%v Path:%v Security:%v BodyParams:%v CookieParams:%v HeaderParams:%v PathParams:%v QueryParams:%v ResponseParams:%v}", d, d.HttpMethod, d.Path, d.Security, d.BodyParams, d.CookieParams, d.HeaderParams, d.PathParams, d.QueryParams, d.ResponseParams)
}

type DocInterface interface {
	SetDoc(doc interface{}) error
	GetDocHttpParams() []*DocHttpParams
	SetDocHttpParams() error
}
