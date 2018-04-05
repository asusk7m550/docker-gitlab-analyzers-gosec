# Go AST Scanner analyzer

GitLab Analyzer for running [Go AST Scanner](https://github.com/GoASTScanner/gas) tool on provided
source code and generate a compatible report.

## How to use

1. `cd` into the directory of the source code you want to scan
1. Run the Docker image:

    ```sh
    docker run \
      --interactive --tty --rm \
      --volume "$PWD":/tmp/app \
      registry.gitlab.com/gitlab-org/security-products/analyzers/go-ast-scanner /tmp/app
    ```

1. The results will be stored in `go-ast-scanner-report.json` in the source code directory.

## Development

Running the analyzer:

```sh
# With Docker
docker run \
  --interactive --tty --rm \
  --volume "$PWD":/analyzer \
  --volume /path/to/source/code:/tmp/app \
  golang /analyzer/run.sh /tmp/app

# Without Docker (not recommended)
./run.sh /path/to/source/code
```

## Versioning and release process

TODO

# Contributing

If you want to help and extend the list of supported scanners, read the
[contribution guidelines](CONTRIBUTING.md).
