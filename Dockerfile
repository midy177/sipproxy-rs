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
ARG GEO_FAIL_OPEN="true"
ARG THREAT_CACHE="true"
ARG THREAT_RETRIES="3"
ARG THREAT_ALLOW_PARTIAL="true"
ARG THREAT_FAIL_OPEN="true"
RUN mkdir -p /etc/sigproxy /var/lib/sigproxy-rs/geo /var/lib/sigproxy-rs/threat

RUN if [ -n "$GEO_COUNTRIES" ]; then \
        if [ "$GEO_ALLOW_PARTIAL" = "true" ]; then GEO_PARTIAL_FLAG="--allow-partial"; else GEO_PARTIAL_FLAG=""; fi; \
        /usr/local/bin/sigproxy geo-cache build \
            --countries "$GEO_COUNTRIES" \
            --output /var/lib/sigproxy-rs/geo/geo.sgeo \
            --retries "$GEO_RETRIES" \
            $GEO_PARTIAL_FLAG \
        || if [ "$GEO_FAIL_OPEN" = "true" ]; then \
            echo "WARN: failed to build geo cache during image build; continuing without prebuilt geo cache"; \
        else \
            exit 1; \
        fi; \
    fi

RUN if [ "$THREAT_CACHE" = "true" ]; then \
        if [ "$THREAT_ALLOW_PARTIAL" = "true" ]; then THREAT_PARTIAL_FLAG="--allow-partial"; else THREAT_PARTIAL_FLAG=""; fi; \
        /usr/local/bin/sigproxy threat-cache build \
            --output /var/lib/sigproxy-rs/threat/threat.sthr \
            --retries "$THREAT_RETRIES" \
            $THREAT_PARTIAL_FLAG \
        || if [ "$THREAT_FAIL_OPEN" = "true" ]; then \
            echo "WARN: failed to build threat cache during image build; continuing without prebuilt threat cache"; \
        else \
            exit 1; \
        fi; \
    fi

ENTRYPOINT ["/usr/local/bin/sigproxy"]
CMD ["run", "--config", "/etc/sigproxy/config.toml"]
