# hs-tailscale

A Haskell library for building standalone Tailscale services, providing networking capabilities equivalent to Tailscale's Golang library. Write peer-to-peer networked applications in Haskell using Tailscale's mesh VPN.

## Overview

`hs-tailscale` enables you to build Haskell applications that can:
- Connect to Tailscale mesh networks
- Accept incoming connections from peers (listeners)
- Establish outgoing connections to peers (dialers)
- Discover and communicate with other nodes on your tailnet

This library provides the same core functionality as Tailscale's Go library (`tailscale.com/tsnet`), allowing you to write standalone Tailscale services entirely in Haskell.

## Features

- **Client Management**: Connect to and manage Tailscale network state
- **Network Listeners**: Accept incoming connections on your tailnet
- **Network Dialers**: Establish outbound connections to peers
- **Peer Discovery**: Find and communicate with other nodes
- **Type-Safe API**: Leverages Haskell's type system for safe networking
- **Authentication**: Integrate with Tailscale's control plane
- **Configuration Management**: Persistent configuration and state

## Installation

Add to your `package.yaml` or `.cabal` file:

```yaml
dependencies:
  - tailscale >= 0.1.0.0
```

Or with cabal:

```bash
cabal install tailscale
```

## Quick Start

### Simple Echo Server

```haskell
{-# LANGUAGE OverloadedStrings #-}

import Network.Tailscale

main :: IO ()
main = do
  -- Load configuration
  config <- loadConfig
  
  -- Create a Tailscale client
  client <- newClient config
  
  -- Authenticate (you'll need an auth key from Tailscale)
  let authKey = AuthKey "tskey-your-auth-key"
  authResult <- authenticate authKey
  
  case authResult of
    Right token -> do
      -- Connect to Tailscale network
      connectClient client token
      
      -- Create a listener on port 8080
      let lConfig = defaultListenerConfig (Port 8080)
      listener <- newListener client lConfig
      listen listener
      
      -- Accept and handle connections
      conn <- accept listener
      print $ "Connection from: " <> show (connPeer conn)
      
    Left err -> putStrLn $ "Auth failed: " <> show err
```

### Simple Client

```haskell
{-# LANGUAGE OverloadedStrings #-}

import Network.Tailscale

main :: IO ()
main = do
  config <- loadConfig
  client <- newClient config
  
  -- Authenticate and connect
  Right token <- authenticate (AuthKey "tskey-your-auth-key")
  connectClient client token
  
  -- List available peers
  peers <- listPeers client
  
  -- Connect to a peer
  let dialer = newDialer client defaultDialerConfig
  conn <- dialPeer dialer (peerID $ head peers) (Port 8080)
  
  -- Use the connection...
  closeConnection conn
  disconnectClient client
```

## Architecture

The library is organized into several modules:

### Core Modules

- **Network.Tailscale**: Main module that re-exports all functionality
- **Network.Tailscale.Types**: Core type definitions (Node, Peer, Connection, etc.)
- **Network.Tailscale.Client**: Client for managing Tailscale network state
- **Network.Tailscale.Config**: Configuration management
- **Network.Tailscale.Auth**: Authentication with Tailscale control plane
- **Network.Tailscale.Listener**: Accept incoming connections
- **Network.Tailscale.Dialer**: Establish outgoing connections

### Key Types

```haskell
-- A Tailscale client
data Client

-- A node in the network (this device)
data Node = Node
  { nodeID :: NodeID
  , nodeKey :: NodeKey
  , nodeName :: Text
  , nodeAddresses :: [TailscaleAddr]
  , ...
  }

-- A peer (another device on the network)
data Peer = Peer
  { peerID :: PeerID
  , peerName :: Text
  , peerAddresses :: [TailscaleAddr]
  , peerStatus :: PeerStatus
  , ...
  }

-- An active connection
data Connection = Connection
  { connPeer :: Peer
  , connLocalAddr :: Endpoint
  , connRemoteAddr :: Endpoint
  , connState :: ConnectionState
  , ...
  }
```

## Authentication

To use this library, you'll need:

1. A Tailscale account
2. An auth key from the [Tailscale admin console](https://login.tailscale.com/admin/settings/keys)

Auth keys can be:
- **Reusable**: Can be used multiple times
- **Ephemeral**: Node is removed when it goes offline
- **Tagged**: Associates the node with specific ACL tags

## Examples

The `examples/` directory contains:

- **EchoServer.hs**: A simple server that accepts connections
- **EchoClient.hs**: A client that connects to peers

Build and run examples:

```bash
cabal build all
cabal run tailscale-echo-server
cabal run tailscale-echo-client
```

## Implementation Status

This is an initial implementation that provides the API structure and core types for building Tailscale services in Haskell.

### Current Status

✅ Core type definitions
✅ Client management API
✅ Listener API for accepting connections
✅ Dialer API for establishing connections
✅ Configuration management
✅ Authentication framework
✅ Example programs

### Future Work

- WireGuard protocol integration
- Full control plane communication
- Real peer discovery and connection establishment
- DNS resolution within tailnet
- ACL enforcement
- Connection pooling and management
- Local peer discovery (mDNS)
- Relay (DERP) support

## Contributing

Contributions are welcome! This library is in early development and there's much to do:

- Implement WireGuard integration
- Add control plane API calls
- Improve error handling
- Add comprehensive tests
- Enhance documentation
- Add more examples

## Related Projects

- [Tailscale](https://tailscale.com/) - The mesh VPN service
- [tsnet (Go)](https://pkg.go.dev/tailscale.com/tsnet) - Official Go library
- [WireGuard](https://www.wireguard.com/) - The underlying VPN protocol

## License

BSD-3-Clause

## Author

Ian Duncan <ian@iankduncan.com>
