.PHONY: all build release check test test-verbose fmt fmt-check lint clean doc ci

all: build

build:
	cargo build

release:
	cargo build --release

check:
	cargo check

test:
	cargo test

test-verbose:
	cargo test -- --nocapture

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

lint:
	cargo clippy --all-targets --all-features -- -D warnings

doc:
	cargo doc --no-deps

clean:
	cargo clean

ci: fmt-check lint test
