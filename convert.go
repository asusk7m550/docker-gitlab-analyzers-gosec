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
		if w.ConfidenceLevel() >= minLevel {
			issues = append(issues, issue.Issue{
				Category:    issue.CategorySast,
				Scanner:     scanner,
				Message:     r.Details,
				Severity:    Level(r.Severity),
				Confidence:  Level(r.Confidence),
				CompareKey:  r.CompareKey(),
				Location:    r.Location(),
				Identifiers: r.Identifiers(),
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
	return strings.Join([]string{r.Filepath(), r.Code, r.RuleID}, ":")
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
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	RuleID     string `json:"rule_id"`
	Details    string `json:"details"`
	File       string `json:"file"`
	Code       string `json:"code"`
	Line       string `json:"line"`
}

// ConfidenceLevel tunrs the confidence into an integer so that it can be compared.
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

// Level returns the normalized severity or confidence.
// Gosec provides same values for both properties.
// See https://github.com/securego/gosec/blob/893b87b34342eadd448aba7638c5cc25f7ad26dd/issue.go#L63-L73
func Level(s string) issue.Level {
	switch s {
	case "HIGH":
		return issue.LevelHigh
	case "MEDIUM":
		return issue.LevelMedium
	case "LOW":
		return issue.LevelLow
	}
	return issue.LevelUnknown
}

// Identifiers returns the normalized identifiers of the vulnerability.
func (r Result) Identifiers() []issue.Identifier {
	return []issue.Identifier{
		r.GosecIdentifier(),
	}
}

// GosecIdentifier returns a structured Identifier for a brakeman Warning Code
func (r Result) GosecIdentifier() issue.Identifier {
	return issue.Identifier{
		Type:  "gosec_rule_id",
		Name:  fmt.Sprintf("Gosec Rule ID %s", r.RuleID),
		Value: r.RuleID,
	}
}
