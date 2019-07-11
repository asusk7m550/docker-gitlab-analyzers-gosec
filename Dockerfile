FROM securego/gosec:2.0.0

RUN apk --no-cache add git
COPY /analyzer /
ENTRYPOINT []
CMD ["/analyzer", "run"]
