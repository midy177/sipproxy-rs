FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iputils-ping \
        netcat-openbsd \
        procps \
        sngrep \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
COPY --chmod=755 dist/linux-${TARGETARCH}/sigproxy /usr/local/bin/sigproxy

RUN mkdir -p /etc/sigproxy

ENTRYPOINT ["/usr/local/bin/sigproxy"]
CMD ["run", "--config", "/etc/sigproxy/config.toml"]
