#!/bin/bash

usage="$(basename "$0") [-h] app_path [output_path]

where:
    -h  show this help text
    app_path The absolute path to the source code of the project you want to analyze.
    output_path The absolute path where the analyzer will output the report file."

while getopts 'h' option; do
  case "$option" in
    h) echo "$usage"
       exit
       ;;
    :) printf "missing argument for -%s\n" "$OPTARG" >&2
       echo "$usage" >&2
       exit 1
       ;;
   \?) printf "illegal option: -%s\n" "$OPTARG" >&2
       echo "$usage" >&2
       exit 1
       ;;
  esac
done
shift $((OPTIND - 1))

if [ $# -ne 1 -a $# -ne 2 ] ; then
  echo "$usage"
  exit
fi

app_path=$1

if [ -z $2 ]; then
  output_path=$app_path
else
  output_path=$2
  # Ensure output path exists
  mkdir -p $output_path
fi

export GOPATH=$GOPATH:/tmp

# Install Go AST Scanner
echo "Installing Go AST Scanner..."
go get github.com/GoASTScanner/gas/cmd/gas/...

# CD to application dir to execute Go AST Scanner there
cd $app_path

# Install project dependencies
echo "Installing project dependencies..."
go get

# Run  Go AST Scanner
echo "Running Go AST Scanner..."
gas -fmt=json -out=$output_path/go-ast-scanner-report.json ./...

# gas exits with 1 if any vuln has been found... so check report file too
if [ $? -ne 0 -a ! -e $output_path/go-ast-scanner-report.json ]; then
  echo "Could not analyze project at $app_path"
  exit 1
fi
