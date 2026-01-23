# tailscale-api

Haskell client for the Tailscale REST API.

## Features

- Complete coverage of Tailscale control plane API
- Type-safe request/response handling with Aeson
- Support for all authentication methods

## Installation

```cabal
build-depends: tailscale-api
```

## Usage

```haskell
import Tailscale.API

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

## API Coverage

| Endpoint | Functions |
|----------|-----------|
| Devices | `getDevices`, `getDevice`, `deleteDevice`, `authorizeDevice`, `setTags` |
| DNS | `getDNSConfig`, `setDNSConfig`, `getNameServers`, `setNameServers`, etc. |
| Keys | `getKeys`, `getKey`, `createKey`, `deleteKey` |
| ACLs | `getACL`, `setACL`, `previewACLForUser`, `validateACLJSON` |
| Routes | `getRoutes`, `setRoutes` |
| Tailnet | `deleteTailnet` |

## License

BSD-3-Clause
