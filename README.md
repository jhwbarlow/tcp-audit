# tcp-audit

`tcp-audit` is a pluggable system for capturing Linux kernel TCP state change events for archival or further processing.

tcp-audit consists of three parts:

- An `Eventer` plugin which sources TCP state change events via any available means.
- A `Sinker` plugin which processes and/or stores the events in some backing store.
- A processor executable/command, implemented in this module, which simply pipes events between the Eventer and the Sinker until stopped (via an interrupt or `TERM` signal).

## Eventer Plugins

Currently implemented Eventer plugins:

- [TraceFS plugin](https://github.com/jhwbarlow/tcp-audit-tracefs-eventer)

## Sinker Plugins

Currently implemented Sinker plugins:

- [PostgresSQL plugin](https://github.com/jhwbarlow/tcp-audit-pgsql-sink)

## Building a complete system

Once the choice of Eventer and Sinker is made, the three can be combined to make a complete system.

- The `--event` argument to the tcp-audit command specifies the path to the Eventer plugin shared object file.
- The `--sink` argument to the tcp-audit command specifies the path to the Sinker plugin shared object file.

For example: `tcp-audit --event='tcp-audit-tracefs-eventer.so'--sink='tcp-audit-pgsql-sink.so'` if using the TraceFS Eventer and PostgreSQL Sinker.

## Building a complete system using containers

A `Dockerfile` is provided in this repository to build and run the processor executable. However, this is a useless image on its own as it contains no plugins. It is intended to be used as a base which can be extended (i.e. `FROM` in Docker terminology) to create custom container images which included the desired choice of plugins.

Each plugin also contains a Dockerfile in its repository. These Dockerfiles create images which simply act as storage locations for the built plugin shared object files and are not runnable.

The intent is that these images can be used as a source from which to copy the plugins into a final image which contains the complete system.

For example, the following Dockerfile could be used to build a system using the TraceFS Eventer and PostgreSQL Sinker:

```Dockerfile
FROM tcpaudit:latest
COPY --from=tcpaudittracefseventer:latest --chown=nonroot:nonroot /tmp/tcp-audit-tracefs-eventer.so /lib/tcp-audit-tracefs-eventer.so
COPY --from=tcpauditpgsqlsink:latest --chown=nonroot:nonroot /tmp/tcp-audit-pgsql-sink.so /lib/tcp-audit-pgsql-sink.so
USER root:root
ENTRYPOINT [ "/usr/bin/tcp-audit", "--event", "/lib/tcp-audit-tracefs-eventer.so", "--sink", "/lib/tcp-audit-pgsql-sink.so" ]
```

`docker build -t tcpauditcomplete:latest .`

Note that in this case, it is necessary to override the user to `root` (accepting the possible risks if a container breakout were to occur) as the TraceFS Eventer requires it.