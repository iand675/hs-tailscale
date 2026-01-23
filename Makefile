# Makefile for hs-tailscale
#
# This Makefile helps with building the tsnet shared library and the Haskell package.

.PHONY: all build-go clean help

# Default target
all: build-go

# Build the Go shared library for tsnet FFI
build-go:
	@echo "Building tsnet shared library..."
	cd go && go mod tidy && go build -buildmode=c-shared -o ../libtsnet.so tsnet_ffi.go
	@echo "Built libtsnet.so"
	@echo ""
	@echo "To use the tsnet library in your Haskell project:"
	@echo "  1. Copy libtsnet.so to a directory in your library path, or"
	@echo "  2. Set LD_LIBRARY_PATH to include this directory"
	@echo "  3. Link with -ltsnet when building"

# Build for macOS (produces .dylib)
build-go-darwin:
	@echo "Building tsnet shared library for macOS..."
	cd go && go mod tidy && go build -buildmode=c-shared -o ../libtsnet.dylib tsnet_ffi.go
	@echo "Built libtsnet.dylib"

# Clean build artifacts
clean:
	rm -f libtsnet.so libtsnet.dylib libtsnet.h
	rm -rf go/go.sum
	rm -rf dist-newstyle

# Help
help:
	@echo "hs-tailscale Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build the Go shared library (default)"
	@echo "  build-go     - Build libtsnet.so (Linux)"
	@echo "  build-go-darwin - Build libtsnet.dylib (macOS)"
	@echo "  clean        - Remove build artifacts"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "After building, you can build the Haskell library with:"
	@echo "  cabal build"
	@echo ""
	@echo "To use tsnet functionality, link against libtsnet.so"
