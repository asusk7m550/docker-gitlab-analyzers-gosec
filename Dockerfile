FROM golang

RUN apt-get update && apt-get install -y ssh
RUN go get github.com/securego/gosec/cmd/gosec/...
COPY /analyzer /
ENTRYPOINT []
CMD ["/analyzer", "run"]
