package main

import (
	"io"
	"os"
	"os/exec"

	"github.com/urfave/cli"
)

const (
	pathPkg    = "app"
	pathGoSrc  = "/go/src"
	pathGoPkg  = pathGoSrc + "/" + pathPkg
	pathOutput = "/tmp/gas.json"
	pathGAS    = "/go/bin/gas"
)

func analyzeFlags() []cli.Flag {
	return []cli.Flag{}
}

func analyze(c *cli.Context, path string) (io.ReadCloser, error) {
	var cmd *exec.Cmd
	var err error

	var setupCmd = func(cmd *exec.Cmd) *exec.Cmd {
		cmd.Env = os.Environ()
		cmd.Stdout = c.App.Writer
		cmd.Stderr = c.App.Writer
		return cmd
	}

	// We don't control the directory where the source code is mounted
	// but Go requires the code to be within $GOPATH.
	// We could create a symlink but that wouldn't work with GAS,
	// so we have to copy all the project source code
	// to some directory under $GOPATH/src.
	// TODO: make it possible to specify the exact path of the package.
	cmd = setupCmd(exec.Command("cp", "-r", path, pathGoPkg))
	err = cmd.Run()
	if err != nil {
		return nil, err
	}

	// GAS needs the dependency to be fetched.
	cmd = setupCmd(exec.Command("go", "get", "./..."))
	cmd.Dir = pathGoPkg
	err = cmd.Run()
	if err != nil {
		return nil, err
	}

	// NOTE: GAS exit with status 1 if some vulnerabilities have been found.
	// This can be disabled by setting the -quiet flag but then
	// GAS returns no output when it can't find any vulnerability.
	// See https://github.com/GoASTScanner/gas/blob/master/cmd/gas/main.go
	cmd = setupCmd(exec.Command(pathGAS, "-fmt=json", "-out="+pathOutput, "./..."))
	cmd.Dir = pathGoPkg
	cmd.Run()
	return os.Open(pathOutput)
}
