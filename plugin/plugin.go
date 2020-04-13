package plugin

import (
	"os"
	"path/filepath"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/plugin"
)

// Match checks the filename and makes sure this is a go project
func Match(path string, info os.FileInfo) (bool, error) {
	if filepath.Ext(info.Name()) == ".go" {
		return true, nil
	}
	return false, nil
}

func init() {
	plugin.Register("gosec", Match)
}
