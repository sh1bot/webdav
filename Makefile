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
#
# For the smallest possible binary, `make build-min` rebuilds the standard
# library from source on a NIGHTLY toolchain (see the build-min target). One-time:
#   make setup-min    (installs nightly + the rust-src component)
# then:
#   make build-min

TARGET := $(shell uname -m)-unknown-linux-musl
BIN    := target/$(TARGET)/release/tiny-webdav

.PHONY: build build-min setup setup-min clean
build:
	cargo build --release --target $(TARGET)
	@echo "built $(BIN)"

# Thorough size build (~180 KB vs ~525 KB for `build`). The stable knobs
# (opt-level=z, lto, panic=abort in Cargo.toml) can't touch the *precompiled*
# std, so most of the binary is std + musl that never gets size-optimized or
# dead-code-eliminated. Rebuilding std from source fixes that: -Z build-std
# applies our release profile (size opt + LTO + function-sectioning) to std
# itself, and -C panic=immediate-abort compiles out panic *messages* — which is
# what drags in the bulk of core::fmt. This uses UNSTABLE flags: it needs the
# nightly toolchain, the rust-src component, and the musl target for its CRT
# startup objects (see setup-min). The exact panic flag is nightly-version
# specific (older nightlies spelled it -Z build-std-features=panic_immediate_abort).
# Same output path as `build`, so the two overwrite each other.
build-min:
	RUSTFLAGS="-Zunstable-options -Cpanic=immediate-abort" \
		cargo +nightly build --release --target $(TARGET) \
		-Z build-std=std,panic_abort
	@echo "built $(BIN) (build-std, minimal)"

setup:
	rustup target add $(TARGET)

setup-min:
	rustup toolchain install nightly
	rustup +nightly component add rust-src
	rustup +nightly target add $(TARGET)

clean:
	cargo clean
