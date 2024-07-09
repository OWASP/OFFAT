package main

import (
	"flag"
	"log"

	"github.com/OWASP/OFFAT/src/pkg/openapi"
)

type Config struct {
	Filename              *string
	IsExternalRefsAllowed *bool
}

func main() {
	config := Config{}

	config.Filename = flag.String("f", "", "OAS/Swagger Doc file path")
	config.IsExternalRefsAllowed = flag.Bool("er", false, "enables visiting other files")
	flag.Parse()

	parser := openapi.Parser{
		Filename:              *config.Filename,
		IsExternalRefsAllowed: *config.IsExternalRefsAllowed,
	}
	parser.Parse(*config.Filename)
	log.Println(*config.Filename)
	log.Println(parser.Version)
}
