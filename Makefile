# Build a fully static (musl) binary for the host's architecture.
#
# The target triple is derived from `uname -m`, so this works on x86_64,
# aarch64, etc. without hard-coding an architecture. One-time per machine:
#   make setup        (installs the musl target via rustup)
# then:
#   make              (static release binary at $(BIN))
#
# Plain `cargo build --release` (no target) still works and gives a normal
# host-native, dynamically linked build — handy for development.

TARGET := $(shell uname -m)-unknown-linux-musl
BIN    := target/$(TARGET)/release/tiny-webdav

.PHONY: build setup clean
build:
	cargo build --release --target $(TARGET)
	@echo "built $(BIN)"

setup:
	rustup target add $(TARGET)

clean:
	cargo clean
