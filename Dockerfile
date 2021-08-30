#docker run --security-opt apparmor=unconfined --cap-add SYS_ADMIN -ti --volume /sys:/sys debian:bullseye-slim bash

FROM golang:1.17 AS builder
COPY . /tmp/src
RUN cd /tmp/src/cmd && \
    GOOS=linux GOARCH=amd64 go build -o /tmp/bin/tcp-audit && \
    chmod 500 /tmp/bin/tcp-audit \
    && ldd /tmp/bin/tcp-audit

FROM gcr.io/distroless/base
USER root:root
COPY --from=builder /tmp/bin/tcp-audit /usr/bin/tcp-audit
# COPY src/cmd/cmd /usr/bin/tcp-audit
ENTRYPOINT [ "/usr/bin/tcp-audit" ]