FROM golang:1.17 AS builder
COPY . /tmp/src
RUN cd /tmp/src/cmd && \
    GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/bin/tcp-audit && \
    chmod 500 /tmp/bin/tcp-audit

FROM gcr.io/distroless/base
USER nonroot:nonroot
COPY --from=builder --chown=nonroot:nonroot /tmp/bin/tcp-audit /usr/bin/tcp-audit
ENTRYPOINT [ "/usr/bin/tcp-audit" ]