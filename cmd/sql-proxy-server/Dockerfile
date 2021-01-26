FROM debian:stretch-slim

RUN apt-get update && apt-get upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    && \
    rm -rf /var/lib/apt/lists/*

COPY sql-proxy-server /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/sql-proxy-server"]
