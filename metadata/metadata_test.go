package metadata_test

import (
	"reflect"
	"testing"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
	"gitlab.com/gitlab-org/security-products/analyzers/gosec/v2/metadata"
)

func TestReportScanner(t *testing.T) {
	want := issue.ScannerDetails{
		ID:      "gosec",
		Name:    "Gosec",
		Version: metadata.ScannerVersion,
		Vendor: issue.Vendor{
			Name: "GitLab",
		},
		URL: "https://github.com/securego/gosec",
	}
	got := metadata.ReportScanner

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}
