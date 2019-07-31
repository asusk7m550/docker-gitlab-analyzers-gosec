package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"

	"github.com/urfave/cli"
)

const (
	pathPkg    = "app"
	pathGoSrc  = "/go/src"
	pathGoPkg  = pathGoSrc + "/" + pathPkg
	pathOutput = "/tmp/gosec.json"
	pathGosec  = "/bin/gosec"
)

func analyzeFlags() []cli.Flag {
	return []cli.Flag{}
}

func analyze(c *cli.Context, projectPath string) (io.ReadCloser, error) {
	var cmd *exec.Cmd
	var err error

	var setupCmd = func(cmd *exec.Cmd) *exec.Cmd {
		cmd.Env = os.Environ()
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd
	}

	// Infer if Go modules need to be disabled.
	_, err = os.Stat(path.Join(projectPath, "go.mod"))
	if os.IsNotExist(err) {
		fmt.Println("Could not find go.mod in project root. Disabling Go modules support by setting GO111MODULE=off.")
		os.Setenv("GO111MODULE", "off")
	}

	// We don't control the directory where the source code is mounted
	// but Go requires the code to be within $GOPATH.
	// We could create a symlink but that wouldn't work with Gosec,
	// so we have to copy all the project source code
	// to some directory under $GOPATH/src.
	// TODO: make it possible to specify the exact path of the package.
	// FIXME: this copy should be necessary when go modules are disabled
	cmd = setupCmd(exec.Command("cp", "-r", projectPath, pathGoPkg))
	err = cmd.Run()
	if err != nil {
		return nil, err
	}

	// Gosec needs the dependency to be fetched.
	cmd = setupCmd(exec.Command("go", "get", "./..."))
	cmd.Dir = pathGoPkg
	err = cmd.Run()
	if err != nil {
		return nil, err
	}

	// NOTE: Gosec exit with status 1 if some vulnerabilities have been found.
	// This can be disabled by setting the -quiet flag but then
	// Gosec returns no output when it can't find any vulnerability.
	// See https://github.com/securego/gosec/blob/master/cmd/gosec/main.go
	cmd = setupCmd(exec.Command(pathGosec, "-fmt=json", "-out="+pathOutput, "./..."))
	cmd.Dir = pathGoPkg
	cmd.Run()
	return os.Open(pathOutput)
}
