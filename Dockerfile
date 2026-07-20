FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        iproute2 \
        iputils-ping \
        libbpf-dev \
        llvm \
        netcat-openbsd \
        procps \
        sngrep \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
COPY --chmod=755 dist/linux-${TARGETARCH}/sigproxy /usr/local/bin/sigproxy
COPY bpf/sigproxy_xdp.c /usr/local/share/sigproxy/sigproxy_xdp.c

RUN clang -O2 -g -target bpf \
        -I/usr/include/$(uname -m)-linux-gnu \
        -c /usr/local/share/sigproxy/sigproxy_xdp.c \
        -o /usr/local/share/sigproxy/sigproxy_xdp.o

ARG GEO_COUNTRIES="all"
ARG GEO_RETRIES="3"
ARG GEO_ALLOW_PARTIAL="true"
RUN mkdir -p /etc/sigproxy /var/lib/sigproxy-rs/geo \
    && if [ -n "$GEO_COUNTRIES" ]; then \
        if [ "$GEO_ALLOW_PARTIAL" = "true" ]; then GEO_PARTIAL_FLAG="--allow-partial"; else GEO_PARTIAL_FLAG=""; fi; \
        /usr/local/bin/sigproxy geo-cache build \
            --countries "$GEO_COUNTRIES" \
            --output /var/lib/sigproxy-rs/geo/geo.sgeo \
            --retries "$GEO_RETRIES" \
            $GEO_PARTIAL_FLAG; \
    fi

ENTRYPOINT ["/usr/local/bin/sigproxy"]
CMD ["run", "--config", "/etc/sigproxy/config.toml"]
