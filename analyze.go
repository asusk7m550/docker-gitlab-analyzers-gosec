package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli"
)

const (
	pathPkg           = "app"
	pathGoSrc         = "/go/src"
	pathGoPkg         = pathGoSrc + "/" + pathPkg
	pathOutput        = "/tmp/gosec.json"
	pathGosec         = "/bin/gosec"
	envVarGoSecConfig = "SAST_GOSEC_CONFIG"
	flagGoSecConfig   = "gosec-config"
)

func analyzeFlags() []cli.Flag {
	return []cli.Flag{
		cli.StringFlag{
			Name:   flagGoSecConfig,
			Usage:  "Relative path to a gosec config file",
			EnvVar: envVarGoSecConfig,
		},
	}
}

func analyze(c *cli.Context, projectPath string) (io.ReadCloser, error) {
	var cmd *exec.Cmd
	var err error

	var setupCmd = func(cmd *exec.Cmd) *exec.Cmd {
		cmd.Env = os.Environ()
		return cmd
	}

	// We don't control the directory where the source code is mounted
	// but Go requires the code to be within $GOPATH.
	// We could create a symlink but that wouldn't work with Gosec,
	// so we have to copy all the project source code
	// to some directory under $GOPATH/src.
	// TODO: make it possible to specify the exact path of the package.
	// FIXME: this copy should be necessary when go modules are disabled
	log.Info("Copying modules into path...")
	cmd = setupCmd(exec.Command("cp", "-r", projectPath, pathGoPkg))
	output, err := cmd.CombinedOutput()
	log.Debugf("Copy output: \n%s", output)
	if err != nil {
		return nil, err
	}

	// Gosec needs the dependency to be fetched.
	log.Info("Fetching dependencies...")
	cmd = setupCmd(exec.Command("go", "get", "./..."))
	cmd.Dir = pathGoPkg
	output, err = cmd.CombinedOutput()
	log.Debugf("Fetch output:\n%s", output)
	if err != nil {
		return nil, err
	}

	// Set up basic gosec arguments
	gosecArgs := []string{"-fmt=json", "-out=" + pathOutput, "./..."}

	// Check if SAST_GOSEC_CONFIG is defined and points to a file
	configFile := c.String(flagGoSecConfig)
	if configFile != "" {
		configPath := filepath.Join(projectPath, configFile)

		st, err := os.Stat(configPath)
		if err != nil {
			return nil, err
		} else if st.IsDir() {
			return nil, fmt.Errorf("%q is a directory", configPath)
		}

		// Prepend -conf PATH to the arguments for gosec
		gosecArgs = append([]string{"-conf", configPath}, gosecArgs...)
	}

	log.Info("Running gosec...")
	cmd = setupCmd(exec.Command(pathGosec, gosecArgs...))
	cmd.Dir = pathGoPkg
	output, err = cmd.CombinedOutput()
	log.Debugf("gosec output:\n%s", output)
	// NOTE: Gosec exit with status 1 if some vulnerabilities have been found.
	if err != nil && cmd.ProcessState.ExitCode() > 1 {
		return nil, err
	}
	return os.Open(pathOutput)
}
