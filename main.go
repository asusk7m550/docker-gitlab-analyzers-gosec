package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli"
	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/cacert"
	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/command"
	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/logutil"
	"gitlab.com/gitlab-org/security-products/analyzers/gosec/v2/plugin"
)

func init() {
	log.SetFormatter(&logutil.Formatter{Project: "gosec"})
}

func main() {
	app := cli.NewApp()
	app.Name = "analyzer"
	app.Usage = "Gosec analyzer for GitLab SAST"
	app.Author = "GitLab"
	app.Email = "gl-security-products@gitlab.com"

	app.Commands = command.NewCommands(command.Config{
		Match:               plugin.Match,
		Analyze:             analyze,
		AnalyzeFlags:        analyzeFlags(),
		AnalyzeAll:          true,
		Convert:             convert,
		CACertImportOptions: cacert.ImportOptions{Path: "/etc/ssl/certs/ca-certificates.crt"},
	})

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
