# hs-tailscale

A Haskell client library for the [Tailscale](https://tailscale.com/) API. This is a direct port of the official [Tailscale Go SDK](https://github.com/tailscale/tailscale/tree/main/client/tailscale).

## Installation

Add `tailscale` to your `build-depends` in your `.cabal` file:

```cabal
build-depends:
  , tailscale
```

## Quick Start

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

## Authentication

The Tailscale API uses API keys for authentication. You can create an API key in the Tailscale admin console at: https://login.tailscale.com/admin/settings/keys

## API Coverage

This library covers the following Tailscale API endpoints:

### Devices

```haskell
-- List all devices
getDevices :: Client -> Maybe DeviceFieldsOpts -> IO (Either TailscaleError [Device])

-- Get a specific device
getDevice :: Client -> Text -> Maybe DeviceFieldsOpts -> IO (Either TailscaleError Device)

-- Delete a device
deleteDevice :: Client -> Text -> IO (Either TailscaleError ())

-- Authorize a device
authorizeDevice :: Client -> Text -> IO (Either TailscaleError ())

-- Set device tags
setTags :: Client -> Text -> [Text] -> IO (Either TailscaleError ())
```

### DNS

```haskell
-- Get/set full DNS configuration
getDNSConfig :: Client -> IO (Either TailscaleError DNSConfig)
setDNSConfig :: Client -> DNSConfig -> IO (Either TailscaleError DNSConfig)

-- Manage nameservers
getNameServers :: Client -> IO (Either TailscaleError [Text])
setNameServers :: Client -> [Text] -> IO (Either TailscaleError DNSNameServersPostResponse)

-- Manage MagicDNS
getDNSPreferences :: Client -> IO (Either TailscaleError DNSPreferences)
setDNSPreferences :: Client -> Bool -> IO (Either TailscaleError DNSPreferences)

-- Manage search paths
getSearchPaths :: Client -> IO (Either TailscaleError [Text])
setSearchPaths :: Client -> [Text] -> IO (Either TailscaleError [Text])
```

### Authentication Keys

```haskell
-- List all keys
getKeys :: Client -> IO (Either TailscaleError [Text])

-- Get key details
getKey :: Client -> Text -> IO (Either TailscaleError Key)

-- Create keys
createKey :: Client -> KeyCapabilities -> IO (Either TailscaleError (Text, Key))
createKeyWithExpiry :: Client -> KeyCapabilities -> NominalDiffTime -> IO (Either TailscaleError (Text, Key))

-- Delete a key
deleteKey :: Client -> Text -> IO (Either TailscaleError ())

-- Helper functions for creating key capabilities
mkReusableKey :: [Text] -> KeyCapabilities
mkEphemeralKey :: [Text] -> KeyCapabilities
mkPreauthorizedKey :: [Text] -> KeyCapabilities
```

### ACLs

```haskell
-- Get ACLs
getACL :: Client -> IO (Either TailscaleError ACL)
getACLHuJSON :: Client -> IO (Either TailscaleError ACLHuJSON)

-- Set ACLs
setACL :: Client -> ACL -> Bool -> IO (Either TailscaleError ACL)
setACLHuJSON :: Client -> ACLHuJSON -> Bool -> IO (Either TailscaleError ACLHuJSON)

-- Preview ACLs
previewACLForUser :: Client -> ACL -> Text -> IO (Either TailscaleError ACLPreview)
previewACLForIPPort :: Client -> ACL -> Text -> IO (Either TailscaleError ACLPreview)

-- Validate ACLs
validateACLJSON :: Client -> Text -> Text -> IO (Either TailscaleError (Maybe ACLTestError))
```

### Routes

```haskell
-- Get device routes
getRoutes :: Client -> Text -> IO (Either TailscaleError Routes)

-- Set enabled routes
setRoutes :: Client -> Text -> [Text] -> IO (Either TailscaleError Routes)
```

### Tailnet

```haskell
-- Delete a tailnet (use with caution!)
deleteTailnet :: Client -> Text -> IO (Either TailscaleError ())
```

## Error Handling

All API functions return `Either TailscaleError a`. The error type covers:

```haskell
data TailscaleError
  = ApiError ErrResponse    -- API returned an error response
  | HttpError Text          -- HTTP-level error
  | JsonError Text          -- JSON parsing error
  | NetworkError Text       -- Network connectivity error
```

## Dependencies

This library uses common Haskell packages:
- `aeson` for JSON serialization
- `http-client` and `http-client-tls` for HTTP
- `text` and `bytestring` for strings
- `time` for timestamps
- `containers` for `Map`

## License

BSD-3-Clause, same as the original Tailscale SDK.
