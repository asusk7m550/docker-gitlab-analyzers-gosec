package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/urfave/cli"
	"gitlab.com/gitlab-org/security-products/analyzers/common/command"
)

func main() {
	app := cli.NewApp()
	app.Name = "analyzer"
	app.Usage = "Go AST Scanner analyzer for GitLab SAST"
	app.Author = "GitLab"
	app.Version = "10.8.0"
	app.Email = "gl-security-products@gitlab.com"

	app.Commands = command.NewCommands(command.Config{
		Match:        match,
		Analyze:      analyze,
		AnalyzeFlags: analyzeFlags(),
		Convert:      convert,
	})

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func match(path string, info os.FileInfo) (bool, error) {
	if filepath.Ext(info.Name()) == ".go" {
		return true, nil
	}
	return false, nil
}
