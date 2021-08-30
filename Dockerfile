#docker run --security-opt apparmor=unconfined --cap-add SYS_ADMIN -ti --volume /sys:/sys debian:bullseye-slim bash

# FROM golang:1.17 AS builder
# COPY . /tmp
# RUN cd /tmp/src/cmd && \
#     GOOS=linux GOARCH=amd64 go build -o /tmp/bin/tcp-audit && \
#     chmod 500 /tmp/bin/tcp-audit
# RUN ldd /tmp/bin/tcp-audit

#FROM busybox AS env-builder
#RUN truncate -s0 /etc/passwd /etc/group && \
#    adduser -h / -g 'TCP Audit' -s /bin/nologin -D -H -u 10999 tcp-audit

FROM gcr.io/distroless/base
#COPY --from=env-builder /etc/passwd /etc/group /etc/
USER root:root
#COPY --from=builder --chown=kube-node-state:kube-node-state /tmp/bin/kube-node-state /usr/bin/kube-node-state
# COPY --from=builder /tmp/bin/tcp-audit /usr/bin/tcp-audit
COPY src/cmd/cmd /usr/bin/tcp-audit
ENTRYPOINT [ "/usr/bin/tcp-audit" ]