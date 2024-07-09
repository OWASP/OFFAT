package openapi

import (
	"errors"
	"log"
	"strings"

	"github.com/OWASP/OFFAT/src/pkg/utils"
	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi3"
)

type Parser struct {
	Version               string
	Filename              string
	IsOpenApi             bool // else Swagger
	IsValid               bool
	IsExternalRefsAllowed bool
}

func (p *Parser) Parse(filename string) (err error) {
	var contentType string
	switch {
	case strings.HasSuffix(filename, ".json"):
		contentType = utils.JSON
	case strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml"):
		contentType = utils.YAML
	default:
		return errors.New("invalid file extension")
	}

	// Detect Doc Version
	var head struct {
		OpenAPI string `json:"openapi" yaml:"openapi"`
		Swagger string `json:"swagger" yaml:"swagger"`
	}

	if err := utils.Read(filename, &head, contentType); err != nil {
		return err
	}

	if head.OpenAPI != "" {
		p.Version = head.OpenAPI
	} else if head.Swagger != "" {
		p.Version = head.Swagger
	} else {
		return errors.New("invalid OAS/swagger version")
	}

	// Parse documentation
	switch {
	case p.Version == "3" || strings.HasPrefix(p.Version, "3."):
		loader := openapi3.NewLoader()
		loader.IsExternalRefsAllowed = p.IsExternalRefsAllowed

		doc, err := loader.LoadFromFile(p.Filename)
		if err != nil {
			log.Fatalln("Loading error:", err)
			return err
		}

		var opts []openapi3.ValidationOption
		// if !*defaults {
		// 	opts = append(opts, openapi3.DisableSchemaDefaultsValidation())
		// }
		// if !*examples {
		// 	opts = append(opts, openapi3.DisableExamplesValidation())
		// }
		// if !*patterns {
		// 	opts = append(opts, openapi3.DisableSchemaPatternValidation())
		// }

		if err = doc.Validate(loader.Context, opts...); err != nil {
			log.Fatalln("Validation error:", err)
		}

	case p.Version == "2" || strings.HasPrefix(p.Version, "2."):
		// if *defaults != defaultDefaults {
		// 	log.Fatal("Flag --defaults is only for OpenAPIv3")
		// }
		// if *examples != defaultExamples {
		// 	log.Fatal("Flag --examples is only for OpenAPIv3")
		// }
		// if *ext != defaultExt {
		// 	log.Fatal("Flag --ext is only for OpenAPIv3")
		// }
		// if *patterns != defaultPatterns {
		// 	log.Fatal("Flag --patterns is only for OpenAPIv3")
		// }

		var doc openapi2.T
		if err := utils.Read(filename, &doc, contentType); err != nil {
			return err
		}

	default:
		return errors.New("missing or incorrect 'openapi' or 'swagger' field")
	}

	return nil
}
