# hs-tailscale

A comprehensive Haskell client library for [Tailscale](https://tailscale.com/). This is a direct port of the official [Tailscale Go SDK](https://github.com/tailscale/tailscale/tree/main/client/tailscale).

## Features

- **Control Plane API** - Manage devices, DNS, ACLs, auth keys, and routes
- **LocalAPI** - Communicate with the local tailscaled daemon
- **Pure Haskell Embedded Tailscale** - Run as a Tailscale node with no external dependencies

### Pure Haskell Implementation

This library includes a complete pure Haskell implementation of:

- **WireGuard Protocol** - Noise_IK handshake, ChaCha20-Poly1305 encryption, Curve25519 key exchange
- **DERP Relay Protocol** - NAT traversal via Tailscale's relay servers
- **Control Plane Protocol** - Node registration, network map distribution
- **Userspace Networking** - IP packet parsing and handling

## Installation

Add `tailscale` to your `build-depends` in your `.cabal` file:

```cabal
build-depends:
  , tailscale
```

## Quick Start

### Control Plane API

```haskell
import Tailscale

main :: IO ()
main = do
  -- Create a client with your API key
  client <- newClient "your-tailnet.com" (APIKey "tskey-api-...")

  -- List all devices
  result <- getDevices client Nothing
  case result of
    Left err -> print err
    Right devices -> mapM_ (print . deviceName) devices
```

### LocalAPI (tailscaled daemon)

The LocalAPI lets you interact with the running tailscaled daemon on the local machine:

```haskell
import Tailscale.LocalAPI

main :: IO ()
main = do
  client <- newLocalClient

  -- Get current status
  status <- getStatus client
  case status of
    Left err -> print err
    Right s -> do
      print $ statusBackendState s
      print $ statusTailscaleIPs s

  -- Identify who is connecting (useful in servers)
  whois <- whoIs client "100.64.1.2:54321"
  case whois of
    Left err -> print err
    Right w -> print $ userProfileDisplayName (whoIsUserProfile w)

  -- Get TLS certificates for HTTPS
  cert <- getCertPair client "myhost.tail-scale.ts.net"
  case cert of
    Left err -> print err
    Right (CertPair certPEM keyPEM) -> do
      -- Use with Warp TLS or other server
      putStrLn "Got certificate!"
```

### Server Utilities

Easy integration with Warp or other Haskell web servers:

```haskell
import Tailscale.Server
import Network.Wai.Handler.Warp

main :: IO ()
main = do
  -- Get configuration from Tailscale
  config <- getTailscaleServerConfig
  case config of
    Left err -> error $ show err
    Right cfg -> do
      putStrLn $ "Tailscale IPs: " <> show (tsAddresses cfg)
      putStrLn $ "HTTPS domain: " <> show (tsCertDomain cfg)

      -- Get TLS config for HTTPS
      tlsConfig <- getTailscaleTLSConfig cfg
      case tlsConfig of
        Left err -> error $ show err
        Right tls -> do
          -- Write certs to temp files for WarpTLS
          writeTLSCredentials tls "/tmp/cert.pem" "/tmp/key.pem"
          -- ... configure WarpTLS with these files
```

### Embedded Tailscale (Pure Haskell)

Run Tailscale embedded in your application:

```haskell
import Tailscale.Embedded

main :: IO ()
main = do
  -- Create an embedded Tailscale instance
  ts <- newTailscale defaultConfig
    { tsHostname = "my-haskell-app"
    , tsAuthKey = Just "tskey-auth-..."  -- For headless operation
    }

  -- Start and connect to the tailnet
  result <- start ts
  case result of
    Left (TailscaleAuthRequired authURL) -> do
      putStrLn $ "Please authenticate at: " <> show authURL
    Left err -> error $ show err
    Right () -> pure ()

  -- Get our Tailscale IPs
  (ipv4, ipv6) <- tailscaleIPs ts
  putStrLn $ "IPv4: " <> show ipv4
  putStrLn $ "IPv6: " <> show ipv6

  -- Listen for connections
  listener <- listen ts "tcp" 8080
  case listener of
    Left err -> error $ show err
    Right ln -> do
      putStrLn "Listening on Tailscale network..."
      forever $ do
        conn <- accept ln
        -- Handle connection...
        close conn

  stop ts
```

#### Dialing Other Nodes

```haskell
main :: IO ()
main = do
  ts <- newTailscale defaultConfig
  _ <- start ts

  -- Connect to another Tailscale node
  result <- dial ts "tcp" "other-host:22"
  case result of
    Left err -> error $ show err
    Right conn -> do
      _ <- send conn "Hello!"
      response <- recv conn 1024
      print response
      close conn
```

#### Using withTailscale

```haskell
main :: IO ()
main = do
  result <- withTailscale defaultConfig $ \ts -> do
    (ipv4, _) <- tailscaleIPs ts
    putStrLn $ "Connected with IP: " <> show ipv4
    -- Your application logic here
    pure ()
  case result of
    Left err -> error $ show err
    Right () -> pure ()
```

## API Reference

### Control Plane API

| Module | Functions |
|--------|-----------|
| **Device** | `getDevices`, `getDevice`, `deleteDevice`, `authorizeDevice`, `setAuthorized`, `setTags` |
| **DNS** | `getDNSConfig`, `setDNSConfig`, `getNameServers`, `setNameServers`, `getDNSPreferences`, `setDNSPreferences`, `getSearchPaths`, `setSearchPaths` |
| **Keys** | `getKeys`, `getKey`, `createKey`, `createKeyWithExpiry`, `deleteKey`, `mkReusableKey`, `mkEphemeralKey`, `mkPreauthorizedKey` |
| **ACL** | `getACL`, `getACLHuJSON`, `setACL`, `setACLHuJSON`, `previewACLForUser`, `previewACLForIPPort`, `validateACLJSON` |
| **Routes** | `getRoutes`, `setRoutes` |
| **Tailnet** | `deleteTailnet` |

### LocalAPI

| Function | Description |
|----------|-------------|
| `getStatus` | Get full daemon status with peers |
| `getStatusWithoutPeers` | Get status without peer info (faster) |
| `whoIs` | Identify who owns a remote address |
| `getCertPair` | Get TLS certificate for a domain |
| `getPrefs` | Get current preferences |
| `ping` | Ping a peer |
| `getServeConfig` / `setServeConfig` | Manage Tailscale Serve |
| `getNetworkLockStatus` | Get tailnet lock status |

### Embedded (Pure Haskell)

| Function | Description |
|----------|-------------|
| `newTailscale` | Create a new Tailscale instance |
| `start` | Start and connect to tailnet |
| `stop` | Stop the instance |
| `withTailscale` | Bracket for safe resource management |
| `tailscaleIPs` | Get assigned IPs (IPv4, IPv6) |
| `certDomains` | Get certificate domains |
| `isConnected` | Check connection status |
| `selfInfo` | Get info about this node |
| `listen` | Listen for connections |
| `listenTLS` | Listen with TLS |
| `accept` | Accept a connection |
| `dial` | Connect to a peer |
| `send` / `recv` | Send/receive data |
| `close` | Close a connection |

## Error Handling

All API functions return `Either SomeError a`:

```haskell
-- Control Plane API errors
data TailscaleError
  = ApiError ErrResponse    -- API returned an error response
  | HttpError Text          -- HTTP-level error
  | JsonError Text          -- JSON parsing error
  | NetworkError Text       -- Network connectivity error

-- Embedded Tailscale errors
data TailscaleError
  = TailscaleNotStarted
  | TailscaleStartError Text
  | TailscaleConnectionError Text
  | TailscaleListenError Text
  | TailscaleDERPError Text
  | TailscaleAuthRequired Text  -- Contains auth URL for interactive login
```

## Dependencies

**Core library**:
- `aeson` - JSON serialization
- `http-client` / `http-client-tls` - HTTP client
- `text` / `bytestring` - String types
- `time` - Timestamps
- `containers` - Map type
- `network` - Socket operations
- `directory` / `filepath` - File operations

**Embedded Tailscale**:
- `crypton` - Cryptographic primitives (ChaCha20-Poly1305, Curve25519, BLAKE2s)
- `memory` - ByteArray operations
- `base64-bytestring` - Base64 encoding
- `stm` - Software transactional memory for concurrency

## License

BSD-3-Clause, same as the original Tailscale SDK.

## Related Projects

- [Tailscale Go SDK](https://github.com/tailscale/tailscale/tree/main/client/tailscale)
- [Caddy Tailscale Plugin](https://github.com/tailscale/caddy-tailscale) - Similar concept for Caddy
