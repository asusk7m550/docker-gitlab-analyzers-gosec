FROM securego/gosec:1.2.0

RUN apk --no-cache add git
COPY /analyzer /
ENTRYPOINT []
CMD ["/analyzer", "run"]
