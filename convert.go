package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
	cweinfo "gitlab.com/gitlab-org/security-products/cwe-info-go"
)

const (
	scannerID   = "gosec"
	scannerName = "Gosec"
)

// This tool was previously named GO_AST_SCANNER.
// backward compatibility
const legacyEnvVarConfidenceLevel = "SAST_GO_AST_SCANNER_LEVEL"
const envVarConfidenceLevel = "SAST_GOSEC_LEVEL"

func convert(reader io.Reader, prependPath string) (*issue.Report, error) {
	var doc = struct {
		Issues []Issue
	}{}

	err := json.NewDecoder(reader).Decode(&doc)
	if err != nil {
		return nil, err
	}

	minLevel := minConfidenceLevel() // TODO: extract level from cli context

	var scanner = issue.Scanner{
		ID:   scannerID,
		Name: scannerName,
	}

	issues := []issue.Issue{}
	for _, w := range doc.Issues {
		r := Result{w, prependPath}
		cwe, err := cweinfo.GetCweInfo(r.CWE.ID)

		var title = ""
		var description = ""

		if err == nil {
			title = cwe.Title
			description = cwe.Description
		} else {
			// Use old RuleID as fallback as a precaution. This should not be necessary as all the gosec rules are
			// mapped to CWEs
			title = fmt.Sprintf("Gosec Rule %s", r.RuleID)
			description = r.Details
		}

		if w.ConfidenceLevel() >= minLevel {
			issues = append(issues, issue.Issue{
				Category:    issue.CategorySast,
				Scanner:     scanner,
				Message:     r.Details,
				Severity:    SeverityLevel(r.Severity),
				Confidence:  ConfidenceLevel(r.Confidence),
				CompareKey:  r.CompareKey(),
				Location:    r.Location(),
				Identifiers: r.Identifiers(),
				Name:        title,
				Description: description,
			})
		}
	}

	report := issue.NewReport()
	report.Vulnerabilities = issues
	return &report, nil
}

func minConfidenceLevel() int {
	var value string
	if value = os.Getenv(envVarConfidenceLevel); value == "" {
		if value = os.Getenv(legacyEnvVarConfidenceLevel); value == "" {
			return 0
		}
	}
	level, err := strconv.Atoi(value)
	if err != nil || level > 3 || level < 0 {
		return 0
	}
	return level
}

// Result describes a result with a relative path.
type Result struct {
	Issue
	PrependPath string
}

// Filepath returns the relative path of the affected file.
func (r Result) Filepath() string {
	rel := strings.TrimPrefix(r.File, pathGoPkg)
	return filepath.Join(r.PrependPath, rel)
}

// CompareKey returns a string used to establish whether two issues are the same.
func (r Result) CompareKey() string {
	_, err := cweinfo.GetCweInfo(r.CWE.ID)
	var ruleID = ""
	if err == nil {
		ruleID = fmt.Sprintf("CWE-%s", r.CWE.ID)
	} else {
		// Use old RuleID as fallback as a precaution. This should not be necessary as all the gosec rules are
		// mapped to CWEs
		ruleID = r.RuleID
	}
	return strings.Join([]string{r.Filepath(), r.Line, r.Code, ruleID}, ":")
}

// Location returns a structured Location
func (r Result) Location() issue.Location {
	line, _ := strconv.Atoi(r.Line)
	return issue.Location{
		File:      r.Filepath(),
		LineStart: line,
	}
}

// Issue describes a vulnerability found in the source code.
type Issue struct {
	Severity   string  `json:"severity"`
	Confidence string  `json:"confidence"`
	RuleID     string  `json:"rule_id"`
	Details    string  `json:"details"`
	File       string  `json:"file"`
	Code       string  `json:"code"`
	Line       string  `json:"line"`
	CWE        CweInfo `json:"cwe"`
}

// CweInfo describes cwe information
type CweInfo struct {
	ID  string
	URL string
}

// ConfidenceLevel turns the confidence into an integer so that it can be compared.
func (i Issue) ConfidenceLevel() int {
	switch i.Confidence {
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	default:
		return 0
	}
}

// ConfidenceLevel returns the normalized severity.
// Gosec provides same values for both severity and confidence.
// See https://github.com/securego/gosec/blob/893b87b34342eadd448aba7638c5cc25f7ad26dd/issue.go#L63-L73
func ConfidenceLevel(s string) issue.ConfidenceLevel {
	switch s {
	case "HIGH":
		return issue.ConfidenceLevelHigh
	case "MEDIUM":
		return issue.ConfidenceLevelMedium
	case "LOW":
		return issue.ConfidenceLevelLow
	}
	return issue.ConfidenceLevelUnknown
}

// SeverityLevel returns the normalized severity.
// Gosec provides same values for both severity and confidence.
// See https://github.com/securego/gosec/blob/893b87b34342eadd448aba7638c5cc25f7ad26dd/issue.go#L63-L73
func SeverityLevel(s string) issue.SeverityLevel {
	switch s {
	case "HIGH":
		return issue.SeverityLevelHigh
	case "MEDIUM":
		return issue.SeverityLevelMedium
	case "LOW":
		return issue.SeverityLevelLow
	}
	return issue.SeverityLevelUnknown
}

// Identifiers returns a list of identifiers.
func (r Result) Identifiers() []issue.Identifier {
	var identifiers []issue.Identifier

	gosecIdentifier := issue.Identifier{
		Type:  "gosec_rule_id",
		Name:  fmt.Sprintf("Gosec Rule ID %s", r.RuleID),
		Value: r.RuleID,
	}

	if url, ok := urls[r.RuleID]; ok {
		gosecIdentifier.URL = url
	}

	identifiers = append(identifiers, gosecIdentifier)

	cwe, err := cweinfo.GetCweInfo(r.Issue.CWE.ID)
	if err == nil {
		identifiers = append(identifiers, issue.Identifier{
			Type:  "CWE",
			Name:  fmt.Sprintf("CWE-%s", cwe.ID),
			Value: cwe.ID,
			URL:   fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", cwe.ID),
		})
	}

	return identifiers
}

// URLs for select rules
// Mapping to be replaced with https://github.com/securego/gosec/issues/127
var urls = map[string]string{
	"G101": "https://securego.io/docs/rules/g101.html",
	"G102": "https://securego.io/docs/rules/g102.html",
	"G103": "https://securego.io/docs/rules/g103.html",
	"G104": "https://securego.io/docs/rules/g104.html",
	"G107": "https://securego.io/docs/rules/g107.html",
	"G201": "https://securego.io/docs/rules/g201-g202.html",
	"G202": "https://securego.io/docs/rules/g201-g202.html",
}
