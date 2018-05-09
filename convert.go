package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gitlab.com/gitlab-org/security-products/analyzers/common/issue"
)

const toolID = "go_ast_scanner"

const envVarConfidenceLevel = "SAST_GO_AST_SCANNER_LEVEL"

func convert(reader io.Reader, prependPath string) ([]issue.Issue, error) {
	var doc = struct {
		Issues []Issue
	}{}

	err := json.NewDecoder(reader).Decode(&doc)
	if err != nil {
		return nil, err
	}

	minLevel := minConfidenceLevel() // TODO: extract level from cli context

	issues := []issue.Issue{}
	for _, w := range doc.Issues {
		line, _ := strconv.Atoi(w.Line)
		r := Result{w, prependPath}
		if w.ConfidenceLevel() >= minLevel {
			issues = append(issues, issue.Issue{
				Tool:       toolID,
				File:       r.Filepath(),
				Message:    r.Details,
				Priority:   r.Priority(),
				Line:       line,
				CompareKey: r.CompareKey(),
			})
		}
	}
	return issues, nil
}

func minConfidenceLevel() int {
	value := os.Getenv(envVarConfidenceLevel)
	if value == "" {
		return 0
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

// Priority returns the normalized priority.
func (i Issue) Priority() issue.Priority {
	switch i.Severity {
	case strings.ToUpper(issue.PriorityCritical):
		return issue.PriorityCritical
	case strings.ToUpper(issue.PriorityHigh):
		return issue.PriorityHigh
	case strings.ToUpper(issue.PriorityMedium):
		return issue.PriorityMedium
	case strings.ToUpper(issue.PriorityLow):
		return issue.PriorityLow
	default:
		return issue.PriorityUnknown
	}
	return issue.PriorityUnknown
}
