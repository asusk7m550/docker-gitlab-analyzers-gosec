FROM golang:1.13 AS build
ENV CGO_ENABLED=0 GOOS=linux
WORKDIR /go/src/app
COPY . .
RUN go build -o analyzer

FROM securego/gosec:v2.2.0

RUN apk --no-cache add git

# Install analyzer
COPY --from=build /go/src/app/analyzer /

ENTRYPOINT []
CMD ["/analyzer", "run"]
