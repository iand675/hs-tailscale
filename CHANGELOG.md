# Changelog for tailscale

## 0.1.0.0 (2026-01-22)

### Initial Release

This is the initial release of the `hs-tailscale` library, providing Haskell bindings for Tailscale networking.

#### Features

* **Core Types**: Complete type definitions for Tailscale networking
  - Node, Peer, Connection types
  - Network address and endpoint types
  - Authentication types (AuthKey, AuthToken, DeviceKey)

* **Client Management**: 
  - Create and manage Tailscale client connections
  - Connect/disconnect from Tailscale network
  - Query connection status
  - List and query peers

* **Network Listener**:
  - Accept incoming connections from peers
  - Configurable listener settings
  - Port binding and backlog configuration

* **Network Dialer**:
  - Establish outbound connections to peers
  - Dial by peer ID or address
  - Configurable timeout and retry settings

* **Configuration**:
  - Configuration management and persistence
  - Support for custom control plane URLs
  - State directory management

* **Authentication**:
  - Authentication framework for Tailscale control plane
  - Device key generation and management
  - Token renewal support

#### Documentation

* Comprehensive README with usage examples
* Example programs demonstrating server and client usage
* Haddock documentation for all public APIs

#### Known Limitations

This is an initial implementation that provides the API structure. Full functionality requires:
- WireGuard protocol integration
- Complete control plane communication
- Real peer discovery
- Connection encryption and authentication

See the README for the full roadmap and future work.
