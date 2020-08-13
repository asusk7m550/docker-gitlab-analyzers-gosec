package metadata

import (
	"fmt"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
)

const (
	// AnalyzerVendor is the vendor/maintainer of the analyzer
	AnalyzerVendor = "GitLab"

	// AnalyzerName is the name of the analyzer
	AnalyzerName = scannerName

	scannerVendor = AnalyzerVendor
	scannerURL    = "https://github.com/securego/gosec"

	// scannerID identifies the scanner that generated the report
	scannerID = "gosec"

	// scannerName identifies the scanner that generated the report
	scannerName = "Gosec"

	// Type returns the type of the scan
	Type issue.Category = issue.CategorySast
)

var (
	// AnalyzerVersion is the semantic version of the analyzer and must match the most recent version in CHANGELOG.md
	AnalyzerVersion = "2.10.0"

	// ScannerVersion is the semantic version of the scanner
	// TODO: ensure this version matches the one specified in the Dockerfile
	//       see https://gitlab.com/gitlab-org/gitlab/-/issues/235059
	ScannerVersion = "2.3.0"

	// IssueScanner describes the scanner used to find a vulnerability
	IssueScanner = issue.Scanner{
		ID:   scannerID,
		Name: scannerName,
	}

	// ReportScanner returns identifying information about a security scanner
	ReportScanner = issue.ScannerDetails{
		ID:      scannerID,
		Name:    scannerName,
		Version: ScannerVersion,
		Vendor: issue.Vendor{
			Name: scannerVendor,
		},
		URL: scannerURL,
	}

	// AnalyzerUsage provides a one line usage string for the analyzer
	AnalyzerUsage = fmt.Sprintf("%s %s analyzer v%s", AnalyzerVendor, AnalyzerName, AnalyzerVersion)
)
