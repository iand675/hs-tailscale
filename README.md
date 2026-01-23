# hs-tailscale

A comprehensive Haskell client library for [Tailscale](https://tailscale.com/). This is a direct port of the official [Tailscale Go SDK](https://github.com/tailscale/tailscale/tree/main/client/tailscale).

## Features

- **Control Plane API** - Manage devices, DNS, ACLs, auth keys, and routes
- **LocalAPI** - Communicate with the local tailscaled daemon
- **TSNet** - Embed Tailscale directly in your application (like Caddy does)

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

### TSNet (Embedded Tailscale)

Run Tailscale embedded in your application - your app appears as a node on the tailnet:

```haskell
import Tailscale.TSNet

main :: IO ()
main = do
  -- Create an embedded Tailscale server
  server <- newServer defaultServerConfig
    { serverHostname = Just "my-haskell-app"
    , serverAuthKey = Just "tskey-auth-..."  -- Or Nothing for interactive
    }

  -- Start and wait until connected
  result <- serverUp server
  case result of
    Left err -> error $ show err
    Right () -> pure ()

  -- Get our Tailscale IPs
  (ipv4, ipv6) <- serverTailscaleIPs server
  putStrLn $ "IPv4: " <> show ipv4
  putStrLn $ "IPv6: " <> show ipv6

  -- Listen for connections on the tailnet
  listener <- serverListen server "tcp" ":8080"
  case listener of
    Left err -> error $ show err
    Right ln -> do
      putStrLn "Listening on Tailscale network..."
      -- Accept connections in a loop
      acceptLoop ln

  serverClose server

acceptLoop :: Listener -> IO ()
acceptLoop ln = do
  connResult <- listenerAccept ln
  case connResult of
    Left err -> print err
    Right conn -> do
      remoteAddr <- connRemoteAddr conn
      putStrLn $ "Connection from: " <> show remoteAddr
      -- Handle connection...
      connClose conn
  acceptLoop ln
```

#### Building TSNet

TSNet requires building a shared library from Go:

```bash
# Build the shared library
make build-go

# Or manually:
cd go
go mod tidy
go build -buildmode=c-shared -o ../libtsnet.so tsnet_ffi.go

# Then build your Haskell project with:
cabal build --extra-lib-dirs=/path/to/hs-tailscale
```

#### TSNet with Automatic TLS

```haskell
-- ListenTLS automatically provisions HTTPS certificates
listener <- serverListenTLS server "tcp" ":443"
```

#### TSNet with Funnel (Public Internet)

```haskell
-- Expose to the public internet via Tailscale Funnel
listener <- serverListenFunnel server "tcp" ":443" False
-- Now accessible at https://my-haskell-app.your-tailnet.ts.net from anywhere!
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

### TSNet

| Function | Description |
|----------|-------------|
| `newServer` | Create a new embedded server |
| `serverUp` | Start and wait until connected |
| `serverListen` | Listen on the tailnet |
| `serverListenTLS` | Listen with automatic TLS |
| `serverListenFunnel` | Listen via public internet |
| `serverDial` | Make outbound connections |
| `serverTailscaleIPs` | Get assigned IPs |
| `serverCertDomains` | Get certificate domains |

## Error Handling

All API functions return `Either TailscaleError a` or `Either TSNetError a`:

```haskell
data TailscaleError
  = ApiError ErrResponse    -- API returned an error response
  | HttpError Text          -- HTTP-level error
  | JsonError Text          -- JSON parsing error
  | NetworkError Text       -- Network connectivity error

data TSNetError
  = TSNetStartError Text
  | TSNetListenError Text
  | TSNetDialError Text
  | TSNetReadError Text
  | TSNetWriteError Text
  | TSNetCloseError Text
  | TSNetEOF
```

## Dependencies

**Core library** (no FFI):
- `aeson` - JSON serialization
- `http-client` / `http-client-tls` - HTTP client
- `text` / `bytestring` - String types
- `time` - Timestamps
- `containers` - Map type
- `network` - Socket operations
- `directory` / `filepath` - File operations

**TSNet library** (requires Go):
- libtsnet.so (built from Go code in `go/`)

## License

BSD-3-Clause, same as the original Tailscale SDK.

## Related Projects

- [Tailscale Go SDK](https://github.com/tailscale/tailscale/tree/main/client/tailscale)
- [tsnet](https://pkg.go.dev/tailscale.com/tsnet) - The Go package this ports
- [Caddy Tailscale Plugin](https://github.com/tailscale/caddy-tailscale) - Similar concept for Caddy
