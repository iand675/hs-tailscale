# hs-tailscale Examples

End-to-end examples demonstrating the `wireguard`, `tailscale-api`, and `tsnet` packages with detailed debugging output.

## Building

```bash
cabal build examples
```

## Available Examples

### WireGuard Crypto (`wireguard-crypto-example`)

Demonstrates the cryptographic primitives used by WireGuard:
- Curve25519 key generation and ECDH
- BLAKE2s hashing and key derivation (KDF1, KDF2, KDF3)
- ChaCha20-Poly1305 AEAD encryption/decryption
- Preshared key generation

```bash
cabal run wireguard-crypto-example
```

### Noise Handshake (`noise-handshake-example`)

Demonstrates the Noise_IKpsk2 handshake protocol:
- Initiator and responder state initialization
- Message 1 and Message 2 creation/parsing
- Session key derivation
- Transport data encryption

```bash
cabal run noise-handshake-example
```

### Tailscale API (`tailscale-api-example`)

Demonstrates the Tailscale REST API client:
- Device listing and management
- DNS configuration
- Authentication key management
- Error handling

Requires environment variables:
```bash
export TAILSCALE_API_KEY='tskey-api-...'
export TAILSCALE_TAILNET='your-tailnet.ts.net'
cabal run tailscale-api-example
```

### LocalAPI (`local-api-example`)

Demonstrates the Tailscale LocalAPI (tailscaled daemon):
- Status queries
- WhoIs identity lookups
- Certificate retrieval
- Preferences

Requires tailscaled to be running:
```bash
cabal run local-api-example
```

### Embedded Tailscale (`embedded-tailscale-example`)

Demonstrates the pure Haskell tsnet implementation:
- Creating embedded Tailscale instances
- Connecting to a tailnet
- Listening for connections
- Information queries

Requires an auth key for full functionality:
```bash
export TAILSCALE_AUTHKEY='tskey-auth-...'
export TAILSCALE_HOSTNAME='my-haskell-app'
cabal run embedded-tailscale-example
```

### Control Plane (`control-plane-example`)

Demonstrates the Tailscale control plane protocol:
- Machine key and node key generation
- Registration request/response structures
- Network map parsing
- DERP map configuration

```bash
cabal run control-plane-example
```

### DERP Client (`derp-client-example`)

Demonstrates the DERP relay protocol:
- Frame types and binary format
- Frame parsing and serialization
- Handshake flow
- Ping/pong keepalive

```bash
cabal run derp-client-example
```

### Packet Parsing (`packet-parsing-example`)

Demonstrates IP packet handling:
- IPv4 header parsing
- IPv6 header parsing
- TCP/UDP protocol identification
- Tailscale IP ranges

```bash
cabal run packet-parsing-example
```

## Debug Output

All examples use the `Examples.Debug` module which provides:
- Colored terminal output
- Structured debug messages
- Hex dumps of binary data
- JSON pretty printing
- Timing measurements
- Progress indicators

## Example Output

```
═══════════════════════════════════════════════════════════════════════════════
  WireGuard Cryptographic Primitives Demo
═══════════════════════════════════════════════════════════════════════════════

ℹ This example demonstrates the core cryptographic operations
ℹ used by WireGuard for secure VPN tunneling.
───────────────────────────────────────────────────────────────────────────────

[Step 1] Generating Curve25519 Key Pairs
  → Alice generates her key pair...
⏱ Generate Alice's private key... done (0.000123s)
  Alice Private Key: (hidden for security)
  Alice Public Key (32 bytes):
  0000: a1b2c3d4e5f6...
✓ Key pairs generated successfully
```
