FROM golang:1.12 AS build
# Force the go compiler to use modules
ENV GO111MODULE=on CGO_ENABLED=0 GOOS=linux
WORKDIR /go/src/app
COPY . .
RUN go build -o analyzer

FROM securego/gosec:2.0.0

RUN apk --no-cache add git

# Install analyzer
COPY --from=build /go/src/app/analyzer /

ENTRYPOINT []
CMD ["/analyzer", "run"]
