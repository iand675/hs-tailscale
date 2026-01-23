# tsnet

Pure Haskell embedded Tailscale networking library, similar to Go's tsnet package.

## Overview

The `tsnet` package allows Haskell applications to join a Tailscale network without requiring the tailscaled daemon. Your application appears as a node on the tailnet, able to accept connections from other Tailscale nodes and make outbound connections.

## Features

- **Embedded Tailscale** - Run Tailscale directly in your application
- **Control Plane Protocol** - Register with Tailscale/Headscale control servers
- **DERP Relay** - NAT traversal via Tailscale's relay network
- **LocalAPI Client** - Communicate with tailscaled daemon
- **Server Utilities** - Automatic TLS certificates and caller identification

## Quick Start

### Embedded Mode

```haskell
import Tsnet.Embedded

main :: IO ()
main = do
  ts <- newTailscale defaultConfig
    { tsHostname = "my-haskell-app"
    , tsAuthKey = Just "tskey-auth-..."
    }

  result <- start ts
  case result of
    Left err -> error $ show err
    Right () -> pure ()

  -- Get our Tailscale IPs
  (ipv4, ipv6) <- tailscaleIPs ts
  putStrLn $ "Connected with IP: " <> show ipv4

  -- Listen for connections
  Right listener <- listen ts "tcp" 8080
  forever $ do
    conn <- accept listener
    -- Handle connection...
    close conn
```

### LocalAPI Mode

If you have tailscaled running, you can use the LocalAPI client:

```haskell
import Tsnet.LocalAPI

main :: IO ()
main = do
  client <- newLocalClient

  -- Get current status
  status <- getStatus client
  case status of
    Left err -> print err
    Right s -> print $ statusBackendState s

  -- Identify who is connecting
  whoIsResult <- whoIs client "100.64.1.2:54321"
  case whoIsResult of
    Right whois -> putStrLn $ "Connection from: "
                            <> userProfileDisplayName (whoIsUserProfile whois)
    Left _ -> putStrLn "Unknown"
```

### Server with TLS

```haskell
import Tsnet.Server
import Tsnet.LocalAPI

main :: IO ()
main = do
  result <- getTailscaleServerConfig
  case result of
    Left err -> error $ show err
    Right config -> do
      putStrLn $ "Serving on " <> show (tsAddresses config)

      -- Get TLS certificate
      tlsConfig <- getTailscaleTLSConfig config
      case tlsConfig of
        Right cfg -> do
          writeTLSCredentials cfg "cert.pem" "key.pem"
          -- Use with your TLS server
        Left err -> print err
```

## Module Structure

- `Tsnet` - Main re-export module
- `Tsnet.Embedded` - Embedded Tailscale client
- `Tsnet.LocalAPI` - LocalAPI client for tailscaled
- `Tsnet.LocalAPI.Types` - Types for LocalAPI
- `Tsnet.Server` - Server utilities
- `Tsnet.Control.Protocol` - Control plane protocol types
- `Tsnet.Control.Client` - Control plane client
- `Tsnet.DERP.Protocol` - DERP relay protocol
- `Tsnet.DERP.Client` - DERP relay client
- `Tsnet.Network.Packet` - IP packet parsing

## Requirements

- GHC 8.10 or later
- For embedded mode: Internet connectivity to Tailscale control plane
- For LocalAPI mode: Running tailscaled daemon

## License

BSD-3-Clause
