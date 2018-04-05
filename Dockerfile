FROM golang

COPY run.sh /

ENTRYPOINT ["/run.sh"]

CMD ["--help"]
