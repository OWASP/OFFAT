package parser

import (
	"errors"

	"github.com/getkin/kin-openapi/openapi2"
)

type Swagger struct {
	doc *openapi2.T
}

func (s *Swagger) SetDoc(doc interface{}) error {
	if doc == nil {
		return errors.New("doc ptr cannot be nil")
	}

	t, ok := doc.(*openapi2.T)
	if !ok {
		return errors.New("invalid type, SetDoc expects type *openapi2.T")
	}

	s.doc = t
	return nil
}

func (s *Swagger) GetDocHttpParams() []*DocHttpParams { return nil }
func (s *Swagger) SetDocHttpParams() error            { return nil }
func (s *Swagger) SetBaseUrl(baseUrl string) error    { return nil }
func (s *Swagger) GetBaseUrl() *string                { return nil }
func (s *Swagger) FuzzDocHttpParams()                 {}
