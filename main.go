package main

import (
	"log"
	"os"

	"github.com/urfave/cli"
	"gitlab.com/gitlab-org/security-products/analyzers/common/command"
	"gitlab.com/gitlab-org/security-products/analyzers/gosec/plugin"
)

func main() {
	app := cli.NewApp()
	app.Name = "analyzer"
	app.Usage = "Gosec analyzer for GitLab SAST"
	app.Author = "GitLab"
	app.Email = "gl-security-products@gitlab.com"

	app.Commands = command.NewCommands(command.Config{
		Match:        plugin.Match,
		Analyze:      analyze,
		AnalyzeFlags: analyzeFlags(),
		AnalyzeAll:   true,
		Convert:      convert,
	})

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
