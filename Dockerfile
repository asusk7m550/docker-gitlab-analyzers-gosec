FROM golang

RUN apt-get update && apt-get install -y ca-certificates git-core ssh
RUN go get github.com/GoASTScanner/gas/cmd/gas/...
COPY /analyzer /
ENTRYPOINT []
CMD ["/analyzer", "run"]
