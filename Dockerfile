FROM golang

RUN apt-get update && apt-get install -y ssh
RUN go get github.com/GoASTScanner/gas/cmd/gas/...
COPY /analyzer /
ENTRYPOINT []
CMD ["/analyzer", "run"]
