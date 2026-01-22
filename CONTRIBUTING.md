# Contributing to hs-tailscale

Thank you for your interest in contributing to hs-tailscale! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- GHC 9.14.1 or later
- Cabal 3.0 or later
- Basic understanding of Haskell
- Familiarity with networking concepts
- Knowledge of Tailscale (helpful but not required)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/iand675/hs-tailscale.git
cd hs-tailscale

# Update Cabal package index
cabal update

# Build the library
cabal build

# Build examples
cabal build all

# Run examples
cabal run tailscale-echo-server
cabal run tailscale-echo-client
```

## Development Workflow

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Create a feature branch** from `main`
4. **Make your changes** with clear, focused commits
5. **Test your changes** thoroughly
6. **Submit a pull request** with a clear description

## What to Contribute

### High Priority

- **WireGuard Integration**: Implement actual WireGuard protocol handling
- **Control Plane API**: Complete HTTP client for Tailscale control plane
- **Peer Discovery**: Implement real peer discovery and connection establishment
- **Tests**: Add comprehensive test suite
- **Documentation**: Improve API documentation and examples

### Medium Priority

- **DNS Integration**: Tailnet DNS resolution
- **ACL Support**: Access control list enforcement
- **Connection Pooling**: Efficient connection management
- **Error Handling**: Improve error messages and recovery

### Also Welcome

- Bug fixes
- Performance improvements
- Documentation improvements
- Additional examples
- Platform-specific optimizations

## Code Style

- Follow standard Haskell style guidelines
- Use meaningful variable and function names
- Add Haddock comments for public APIs
- Keep functions focused and composable
- Use type signatures for all top-level functions
- Enable and respect compiler warnings

## Testing

Currently, there is no test suite. Adding tests is a high-priority contribution!

When the test suite exists:
```bash
cabal test
```

## Documentation

- Update README.md if adding new features
- Add Haddock comments to all public APIs
- Update CHANGELOG.md for user-facing changes
- Include examples for new functionality

## Commit Messages

- Use clear, descriptive commit messages
- Start with a verb in present tense (e.g., "Add", "Fix", "Update")
- Reference issue numbers when applicable
- Keep first line under 72 characters
- Add detailed description if needed

Example:
```
Add WireGuard protocol integration

Implements basic WireGuard handshake and encryption using the
wg-haskell library. This enables actual encrypted peer-to-peer
connections.

Fixes #123
```

## Pull Request Process

1. Ensure your code builds without errors
2. Update documentation as needed
3. Add tests for new functionality (when test framework exists)
4. Update CHANGELOG.md
5. Create a clear PR description explaining:
   - What changes were made
   - Why they were necessary
   - How they were tested

## Questions or Need Help?

- Open an issue for bugs or feature requests
- Start a discussion for questions or ideas
- Check existing issues before creating new ones

## License

By contributing, you agree that your contributions will be licensed under the same BSD-3-Clause license as the project.

## Code of Conduct

Be respectful and professional in all interactions. We want this to be a welcoming community for everyone.

## Acknowledgments

Thank you for helping make hs-tailscale better!
