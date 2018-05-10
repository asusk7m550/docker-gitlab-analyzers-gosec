package plugin

import (
	"os"
	"path/filepath"

	"gitlab.com/gitlab-org/security-products/analyzers/common/plugin"
)

func Match(path string, info os.FileInfo) (bool, error) {
	if filepath.Ext(info.Name()) == ".go" {
		return true, nil
	}
	return false, nil
}

func init() {
	plugin.Register("go-ast-scanner", Match)
}
