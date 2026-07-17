BIN ?= sigproxy
CONFIG ?= examples/single-node.toml
VERSION ?= $(shell cargo metadata --no-deps --format-version 1 | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')
IMAGE_REPO ?= 1228022817/sigproxy-rs
IMAGE ?= $(IMAGE_REPO):$(VERSION)
CONTAINER_NAME ?= sigproxy-rs
ZIG_TARGET_AMD64 ?= x86_64-unknown-linux-musl
ZIG_TARGET_ARM64 ?= aarch64-unknown-linux-musl
DOCKER_PLATFORM ?= linux/amd64
DOCKER_PLATFORMS ?= linux/amd64,linux/arm64
DIST_DIR ?= dist

.PHONY: build
build:
	cargo build --bin $(BIN)

.PHONY: release
release:
	cargo build --release --bin $(BIN)

.PHONY: zig-build
zig-build: zig-build-amd64

.PHONY: zig-build-amd64
zig-build-amd64:
	cargo zigbuild --release --bin $(BIN) --target $(ZIG_TARGET_AMD64)
	mkdir -p $(DIST_DIR)/linux-amd64
	cp target/$(ZIG_TARGET_AMD64)/release/$(BIN) $(DIST_DIR)/linux-amd64/$(BIN)

.PHONY: zig-build-arm64
zig-build-arm64:
	cargo zigbuild --release --bin $(BIN) --target $(ZIG_TARGET_ARM64)
	mkdir -p $(DIST_DIR)/linux-arm64
	cp target/$(ZIG_TARGET_ARM64)/release/$(BIN) $(DIST_DIR)/linux-arm64/$(BIN)

.PHONY: zig-build-all
zig-build-all: zig-build-amd64 zig-build-arm64

.PHONY: run
run:
	cargo run --bin $(BIN) -- run --config $(CONFIG)

.PHONY: config-check
config-check:
	cargo run --bin $(BIN) -- config check --config $(CONFIG)

.PHONY: config-init
config-init:
	cargo run --bin $(BIN) -- config init --output config.toml

.PHONY: test
test:
	cargo test

.PHONY: fmt
fmt:
	cargo fmt --check

.PHONY: clippy
clippy:
	cargo clippy --all-targets --all-features -- -D warnings

.PHONY: docker-build
docker-build: zig-build
	docker build --platform $(DOCKER_PLATFORM) -t $(IMAGE) .

.PHONY: docker-build-amd64
docker-build-amd64: zig-build-amd64
	docker build --platform linux/amd64 -t $(IMAGE) .

.PHONY: docker-build-arm64
docker-build-arm64: zig-build-arm64
	docker build --platform linux/arm64 -t $(IMAGE) .

.PHONY: docker-buildx-push
docker-buildx-push: zig-build-all
	docker buildx build --platform $(DOCKER_PLATFORMS) -t $(IMAGE) --push .

.PHONY: docker-run
docker-run:
	docker run --rm --name $(CONTAINER_NAME) \
		-p 5060:5060/udp \
		-p 5060:5060/tcp \
		-p 9100:9100/tcp \
		-v $(PWD)/$(CONFIG):/etc/sigproxy/config.toml:ro \
		$(IMAGE)

.PHONY: docker-shell
docker-shell:
	docker run --rm -it --entrypoint /bin/sh \
		--name $(CONTAINER_NAME)-shell \
		-v $(PWD)/$(CONFIG):/etc/sigproxy/config.toml:ro \
		$(IMAGE)
