// Package kb loads the attack-vector knowledge base that drives dynamic test
// generation. Vectors declare *where* they apply (parameter location, type,
// name patterns, HTTP methods), *what* to send (payloads or a named structural
// attack), and *how* to tell a hit from a miss (detection rules). A default
// library is embedded in the binary; additional user vectors — including
// patterns distilled from public bug-bounty reports — can be merged from a
// directory at runtime.
package kb

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed data/*.yaml
var embedded embed.FS

// Technique identifies how a detector decides a payload triggered a bug.
type Technique string

const (
	TechError      Technique = "error"      // known error signature appears in the response
	TechReflection Technique = "reflection" // payload/marker is echoed back
	TechTime       Technique = "time"       // response is measurably delayed
	TechBoolean    Technique = "boolean"    // true/false payloads yield different responses
	TechStatus     Technique = "status"     // an unexpected status code is returned
	TechDiff       Technique = "diff"       // response differs meaningfully from baseline
)

// KB is a loaded knowledge base.
type KB struct {
	Vectors []*Vector
}

// Vector is a single reusable attack template.
type Vector struct {
	ID          string        `yaml:"id"`
	Class       string        `yaml:"class"`
	Title       string        `yaml:"title"`
	Severity    string        `yaml:"severity"`
	CWE         string        `yaml:"cwe"`
	OWASP       string        `yaml:"owasp"`
	Description string        `yaml:"description"`
	References  []string      `yaml:"references"`
	AppliesTo   Applicability `yaml:"applies_to"`
	Payloads    []Payload     `yaml:"payloads"`
	Detection   Detection     `yaml:"detection"`
	// Structural names a built-in structural attack (e.g. "bola",
	// "mass_assignment", "auth_bypass", "method_tamper") instead of value
	// injection. When set, Payloads may be empty.
	Structural string `yaml:"structural"`
	// Source records where the vector was loaded from (for provenance).
	Source string `yaml:"-"`
}

// Applicability constrains which parameters a vector targets.
type Applicability struct {
	Locations    []string `yaml:"locations"`     // path|query|header|cookie|body
	Types        []string `yaml:"types"`         // string|integer|number|boolean|any
	NamePatterns []string `yaml:"name_patterns"` // regexes matched against param names
	Methods      []string `yaml:"methods"`       // HTTP methods this applies to
}

// Payload is a single injectable value.
type Payload struct {
	Value     string    `yaml:"value"`
	Technique Technique `yaml:"technique"`
	Encoding  string    `yaml:"encoding"` // none|url|base64
	Note      string    `yaml:"note"`
}

// Detection holds signal rules used to judge a response.
type Detection struct {
	ErrorSignatures []string `yaml:"error_signatures"`
	ReflectMarker   bool     `yaml:"reflect_marker"`
	TimeThresholdMs int      `yaml:"time_threshold_ms"`
	StatusCodes     []int    `yaml:"status_codes"`
	BodyRegex       []string `yaml:"body_regex"`
}

// file is the on-disk YAML shape: a list of vectors under a top-level key.
type file struct {
	Vectors []*Vector `yaml:"vectors"`
}

// LoadDefault parses the knowledge base embedded in the binary.
func LoadDefault() (*KB, error) {
	kb := &KB{}
	entries, err := embedded.ReadDir("data")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !isYAML(e.Name()) {
			continue
		}
		data, err := embedded.ReadFile("data/" + e.Name())
		if err != nil {
			return nil, err
		}
		if err := kb.merge(data, "embedded:"+e.Name()); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
	}
	return kb, nil
}

// LoadDir merges every YAML vector file found under dir (recursively).
func (kb *KB) LoadDir(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(d.Name()) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := kb.merge(data, path); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		return nil
	})
}

func (kb *KB) merge(data []byte, source string) error {
	var f file
	if err := yaml.Unmarshal(data, &f); err != nil {
		return err
	}
	for _, v := range f.Vectors {
		if v == nil || v.ID == "" {
			continue
		}
		v.Source = source
		kb.Vectors = append(kb.Vectors, v)
	}
	return nil
}

// Classes returns the distinct vulnerability classes present in the KB.
func (kb *KB) Classes() []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range kb.Vectors {
		if !seen[v.Class] {
			seen[v.Class] = true
			out = append(out, v.Class)
		}
	}
	return out
}

// Filter returns a copy limited to the given classes (nil/empty = all).
func (kb *KB) Filter(classes []string) *KB {
	if len(classes) == 0 {
		return kb
	}
	want := map[string]bool{}
	for _, c := range classes {
		want[strings.ToLower(strings.TrimSpace(c))] = true
	}
	out := &KB{}
	for _, v := range kb.Vectors {
		if want[strings.ToLower(v.Class)] {
			out.Vectors = append(out.Vectors, v)
		}
	}
	return out
}

func isYAML(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}
