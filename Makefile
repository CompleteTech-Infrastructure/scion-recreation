# Paths may be overridden, e.g. make check-toolchain GO=/path/to/go PYTHON=/path/to/python3.
# Each override is one executable path, not a shell command with arguments.
GO ?= go
PYTHON ?= python3
PROTOC ?= protoc

.DEFAULT_GOAL := build
.PHONY: all check-toolchain build test

all: build test

# Check the available baseline, including protoc. No generation is performed.
check-toolchain:
	"$(PYTHON)" tools/check_toolchain.py check --go "$(GO)" --protoc "$(PROTOC)"

# Build/test currently consume Go and Python only; protoc is checked above.
# The runner enforces offline, local-only, read-only module resolution.
build:
	"$(PYTHON)" tools/check_toolchain.py build --go "$(GO)"

test:
	"$(PYTHON)" tools/check_toolchain.py test --go "$(GO)"
