package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
)

func TestConvert(t *testing.T) {
	// Make sure we're backward compatible with the old var name
	levels := []string{
		envVarConfidenceLevel,
		legacyEnvVarConfidenceLevel,
	}
	for _, envLevel := range levels {
		t.Run("With "+envLevel, func(t *testing.T) {
			os.Setenv(envLevel, "3")
			in := `{
				"Issues": [
					{
							"severity": "MEDIUM",
							"confidence": "HIGH",
							"cwe": {
									"ID": "327",
									"URL": "https://cwe.mitre.org/data/definitions/327.html"
							},
							"rule_id": "G501",
							"details": "Blacklisted import crypto/md5: weak cryptographic primitive",
							"file": "/go/src/app/main.go",
							"code": "\"crypto/md5\"",
							"line": "15"
					},
					{
							"severity": "MEDIUM",
							"confidence": "HIGH",
							"cwe": {
									"ID": "326",
									"URL": "https://cwe.mitre.org/data/definitions/326.html"
							},
							"rule_id": "G401",
							"details": "Use of weak cryptographic primitive",
							"file": "/go/src/app/main.go",
							"code": "md5.New()",
							"line": "11"
					},
					{
						"severity": "LOW",
						"confidence": "LOW",
						"rule_id": "xyz",
						"details": "xyz",
						"file": "/go/src/app/main.go",
						"code": "xyz",
						"line": "1"
					},
				{
					"severity": "LOW",
					"confidence": "HIGH",
					"rule_id": "G105",
					"details": "Use of math/big.Int.Exp function should be audited for modulus == 0",
					"file": "/go/src/app/main.go",
					"code": "z.Exp(x, y, m)",
					"line": "15"
				}

				]
			}`

			var scanner = issue.Scanner{
				ID:   "gosec",
				Name: "Gosec",
			}

			r := strings.NewReader(in)
			want := &issue.Report{
				Version: issue.CurrentVersion(),
				Vulnerabilities: []issue.Issue{
					{
						Category:    issue.CategorySast,
						Name:        "Use of a Broken or Risky Cryptographic Algorithm",
						Scanner:     scanner,
						Message:     "Blacklisted import crypto/md5: weak cryptographic primitive",
						Description: "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.",
						CompareKey:  "app/main.go:15:\"crypto/md5\":CWE-327",
						Severity:    issue.SeverityLevelMedium,
						Confidence:  issue.ConfidenceLevelHigh,
						Location: issue.Location{
							File:      "app/main.go",
							LineStart: 15,
						},
						Identifiers: []issue.Identifier{
							{
								Type:  "gosec_rule_id",
								Name:  "Gosec Rule ID G501",
								Value: "G501",
								URL:   "",
							},
							{
								Type:  "CWE",
								Name:  "CWE-327",
								Value: "327",
								URL:   "https://cwe.mitre.org/data/definitions/327.html",
							},
						},
					},
					{
						Category:    issue.CategorySast,
						Name:        "Inadequate Encryption Strength",
						Scanner:     scanner,
						Message:     "Use of weak cryptographic primitive",
						Description: "The software stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required.",
						CompareKey:  "app/main.go:11:md5.New():CWE-326",
						Severity:    issue.SeverityLevelMedium,
						Confidence:  issue.ConfidenceLevelHigh,
						Location: issue.Location{
							File:      "app/main.go",
							LineStart: 11,
						},
						Identifiers: []issue.Identifier{
							{
								Type:  "gosec_rule_id",
								Name:  "Gosec Rule ID G401",
								Value: "G401",
								URL:   "",
							},
							{
								Type:  "CWE",
								Name:  "CWE-326",
								Value: "326",
								URL:   "https://cwe.mitre.org/data/definitions/326.html",
							},
						},
					},
					{
						Category:    issue.CategorySast,
						Name:        "Gosec Rule G105",
						Scanner:     scanner,
						Message:     "Use of math/big.Int.Exp function should be audited for modulus == 0",
						Description: "Use of math/big.Int.Exp function should be audited for modulus == 0",
						CompareKey:  "app/main.go:15:z.Exp(x, y, m):G105",
						Severity:    issue.SeverityLevelLow,
						Confidence:  issue.ConfidenceLevelHigh,
						Location: issue.Location{
							File:      "app/main.go",
							LineStart: 15,
						},
						Identifiers: []issue.Identifier{
							{
								Type:  "gosec_rule_id",
								Name:  "Gosec Rule ID G105",
								Value: "G105",
								URL:   "",
							},
						},
					},
				},
				DependencyFiles: []issue.DependencyFile{},
				Remediations:    []issue.Remediation{},
			}
			got, err := convert(r, "app")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(want, got) {
				t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
			}
		})
	}
}
