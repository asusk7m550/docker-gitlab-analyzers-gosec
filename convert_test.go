package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"gitlab.com/gitlab-org/security-products/analyzers/common/issue"
)

func init() {
	os.Setenv("SAST_GO_AST_SCANNER_LEVEL", "3")
}

func TestConvert(t *testing.T) {
	in := `{
  "Issues": [
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
	r := strings.NewReader(in)
	want := []issue.Issue{
		{
			Tool:       "go_ast_scanner",
			Category:   issue.CategorySast,
			Message:    "Use of math/big.Int.Exp function should be audited for modulus == 0",
			CompareKey: "app/main.go:z.Exp(x, y, m):G105",
			Severity:   issue.LevelLow,
			Confidence: issue.LevelHigh,
			Location: issue.Location{
				File:      "app/main.go",
				LineStart: 15,
			},
			Identifiers: []issue.Identifier{
				{
					Type:  "gas_rule_id",
					Name:  "Go AST Scanner Rule ID G105",
					Value: "G105",
				},
			},
		},
	}
	got, err := convert(r, "app")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}
