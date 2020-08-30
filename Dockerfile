ARG GO_VERSION=1.14

FROM golang:$GO_VERSION-alpine AS build

ARG GOSEC_VERSION=2.3.0
ARG GOSEC_SHA1SUM=c014494fae731b0e45d3bf2e12821fc7d0a92b14

ENV CGO_ENABLED=0 GOOS=linux

WORKDIR /go/src/buildapp
COPY . .

# Install analyzer
RUN go build -o /analyzer

ADD https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_amd64.tar.gz /tmp/gosec.tar.gz
RUN tar xf /tmp/gosec.tar.gz && \
  echo "$GOSEC_SHA1SUM  /tmp/gosec.tar.gz" | sha1sum -c && \
  tar xf /tmp/gosec.tar.gz && \
  rm -f /tmp/gosec.tar.gz && \
  mv gosec /bin/gosec

# Create new base container with a clean $GOPATH
FROM golang:$GO_VERSION-alpine AS base

# Install some packages
RUN apk --no-cache add git ca-certificates gcc libc-dev pkgconf g++ bash make

# Build kafka
RUN git clone https://github.com/edenhill/librdkafka.git && cd librdkafka/ && ./configure --prefix /usr && make && make install && cd && rm -rf librdkafka

# Download kafka for golang
RUN go get -tags musl -u gopkg.in/confluentinc/confluent-kafka-go.v1/kafka


COPY --from=build /analyzer /analyzer
COPY --from=build /bin/gosec /bin/gosec

ENTRYPOINT []
CMD ["/analyzer", "run"]
