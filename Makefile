# Makefile for hs-tailscale

.PHONY: all build test clean format lint help

# Default target
all: build

# Build the library
build:
	cabal build all

# Run tests
test:
	cabal test all

# Clean build artifacts
clean:
	rm -rf dist-newstyle

# Format code with fourmolu
format:
	fourmolu -i src/

# Run hlint
lint:
	hlint src/

# Help
help:
	@echo "hs-tailscale Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build the library (default)"
	@echo "  build   - Build the library"
	@echo "  test    - Run tests"
	@echo "  clean   - Remove build artifacts"
	@echo "  format  - Format code with fourmolu"
	@echo "  lint    - Run hlint"
	@echo "  help    - Show this help message"
