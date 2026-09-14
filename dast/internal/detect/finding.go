// Package detect turns raw execution results into vulnerability findings by
// applying the detection rules attached to each attack vector, comparing
// against per-endpoint baselines to suppress noise. It produces a heuristic
// confidence that the AI triager later refines.
package detect

// Finding is a single candidate (or confirmed) vulnerability.
type Finding struct {
	ID          string   `json:"id"`
	VectorID    string   `json:"vector_id"`
	Class       string   `json:"class"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	CWE         string   `json:"cwe"`
	OWASP       string   `json:"owasp"`
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Endpoint    string   `json:"endpoint"`
	Param       string   `json:"param,omitempty"`
	Location    string   `json:"location,omitempty"`
	Technique   string   `json:"technique,omitempty"`
	Payload     string   `json:"payload,omitempty"`
	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`

	Confidence float64  `json:"confidence"` // 0..1 heuristic pre-triage
	Evidence   Evidence `json:"evidence"`

	// Triage is populated by the AI/heuristic triager.
	Triage *Triage `json:"triage,omitempty"`
}

// Evidence captures why the detector fired.
type Evidence struct {
	RequestMethod     string `json:"request_method"`
	RequestURL        string `json:"request_url,omitempty"`
	StatusCode        int    `json:"status_code"`
	BaselineStatus    int    `json:"baseline_status,omitempty"`
	LatencyMs         int64  `json:"latency_ms,omitempty"`
	BaselineLatencyMs int64  `json:"baseline_latency_ms,omitempty"`
	MatchedSignature  string `json:"matched_signature,omitempty"`
	Snippet           string `json:"snippet,omitempty"`
	Notes             string `json:"notes,omitempty"`
}

// Triage is the verdict produced by the triager.
type Triage struct {
	Verdict     string  `json:"verdict"`    // confirmed | likely | inconclusive | false_positive
	Confidence  float64 `json:"confidence"` // 0..1
	CVSS        float64 `json:"cvss,omitempty"`
	Severity    string  `json:"severity,omitempty"`
	Rationale   string  `json:"rationale,omitempty"`
	Remediation string  `json:"remediation,omitempty"`
	Source      string  `json:"source"` // "ai" | "heuristic"
}
