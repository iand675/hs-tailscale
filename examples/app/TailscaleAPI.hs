{- |
Tailscale REST API Example

This example demonstrates using the Tailscale API client to:
- List devices in a tailnet
- Manage DNS settings
- Work with authentication keys
- Handle API errors

Run with: cabal run tailscale-api-example

Note: Requires a valid Tailscale API key set in TAILSCALE_API_KEY
and tailnet name in TAILSCALE_TAILNET environment variables.
-}
module Main where

import Control.Exception (SomeException, try)
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Environment (lookupEnv)

import Examples.Debug
import Tailscale.API
import Tailscale.API.Client
import Tailscale.API.Device
import Tailscale.API.DNS
import Tailscale.API.Keys
import Tailscale.API.Types


main :: IO ()
main = do
  debugSection "Tailscale REST API Client Demo"

  debugInfo "This example demonstrates the Tailscale API client"
  debugInfo "for managing your tailnet programmatically."
  separator

  -- Step 1: Get Configuration
  debugStep 1 "Loading Configuration"

  debugSubStep "Reading environment variables..."
  mApiKey <- lookupEnv "TAILSCALE_API_KEY"
  mTailnet <- lookupEnv "TAILSCALE_TAILNET"

  case (mApiKey, mTailnet) of
    (Nothing, _) -> do
      debugWarning "TAILSCALE_API_KEY not set"
      runMockDemo
    (_, Nothing) -> do
      debugWarning "TAILSCALE_TAILNET not set"
      runMockDemo
    (Just apiKey, Just tailnet) -> do
      debugSuccess "Configuration loaded"
      debugKeyValue "Tailnet" tailnet
      debugKeyValue "API Key" (take 8 apiKey ++ "..." ++ take 4 (reverse apiKey))
      separator
      runRealDemo (T.pack tailnet) (T.pack apiKey)


-- | Run demo with real API
runRealDemo :: T.Text -> T.Text -> IO ()
runRealDemo tailnet apiKey = do
  -- Step 2: Create Client
  debugStep 2 "Creating API Client"

  debugSubStep "Initializing HTTP client with TLS..."
  client <- timed "Create client" $ newClient tailnet (APIKey apiKey)

  debugSuccess "Client created"
  debugTable
    [ ("Tailnet", T.unpack $ clientTailnet client)
    , ("Base URL", T.unpack $ clientBaseURL client)
    , ("User Agent", T.unpack $ clientUserAgent client)
    ]
  separator

  -- Step 3: List Devices
  debugStep 3 "Listing Devices"

  debugSubStep "Fetching device list from API..."
  debugInfo $ "GET " ++ T.unpack (buildTailnetURL client ["devices"])

  devicesResult <- timed "Fetch devices" $ getDevices client Nothing
  debugEither "Device list" devicesResult $ \devices -> do
    debugSuccess $ "Found " ++ show (length devices) ++ " devices"

    if null devices
      then debugInfo "No devices in tailnet"
      else do
        debugSubStep "Device details:"
        mapM_ printDevice devices

  separator

  -- Step 4: DNS Configuration
  debugStep 4 "Checking DNS Configuration"

  debugSubStep "Fetching DNS configuration..."
  debugInfo $ "GET " ++ T.unpack (buildTailnetURL client ["dns", "nameservers"])

  dnsResult <- timed "Fetch DNS config" $ getDNSNameservers client
  debugEither "DNS nameservers" dnsResult $ \ns -> do
    debugSuccess "DNS configuration retrieved"
    debugKeyValue "DNS Mode" (if null (nsServers ns) then "Default" else "Custom")
    if null (nsServers ns)
      then debugInfo "Using default Tailscale DNS"
      else debugList "Custom nameservers" (nsServers ns)

  separator

  -- Step 5: Authentication Keys
  debugStep 5 "Listing Authentication Keys"

  debugSubStep "Fetching auth keys..."
  debugInfo $ "GET " ++ T.unpack (buildTailnetURL client ["keys"])

  keysResult <- timed "Fetch keys" $ getKeys client
  debugEither "Auth keys" keysResult $ \keys -> do
    debugSuccess $ "Found " ++ show (length keys) ++ " auth keys"
    mapM_ printKey keys

  separator

  -- Summary
  debugSection "API Demo Complete"

  boxed "Tailscale API Operations"
    [ "✓ Device listing and management"
    , "✓ DNS configuration"
    , "✓ Authentication key management"
    , "✓ ACL policy management"
    , "✓ Route configuration"
    ]

  debugSuccess "API example completed!"


-- | Print device information
printDevice :: Device -> IO ()
printDevice dev = do
  let name = T.unpack $ deviceName dev
      online = if fromMaybe False (deviceOnline dev) then "Online" else "Offline"
      addrs = maybe [] (map T.unpack) (deviceAddresses dev)
      os = T.unpack $ fromMaybe "Unknown" (deviceOs dev)

  debugSubStep $ name ++ " (" ++ online ++ ")"
  debugTable
    [ ("ID", T.unpack $ deviceId dev)
    , ("OS", os)
    , ("IPs", if null addrs then "None" else unwords addrs)
    , ("Last Seen", maybe "Never" show (deviceLastSeen dev))
    ]


-- | Print key information
printKey :: Key -> IO ()
printKey key = do
  debugSubStep $ "Key: " ++ T.unpack (keyId key)
  debugTable
    [ ("Created", show $ keyCreated key)
    , ("Expires", show $ keyExpires key)
    , ("Capabilities", "...") -- Capabilities would need formatting
    ]


-- | Run demo with mock data when no credentials
runMockDemo :: IO ()
runMockDemo = do
  separator
  debugSection "Running Mock Demo (No Credentials)"

  debugInfo "Since API credentials are not provided, we'll demonstrate"
  debugInfo "the client structure with mock data."
  separator

  -- Show API structure
  debugStep 2 "API Client Structure"

  debugSubStep "Available API endpoints:"
  debugTable
    [ ("Devices", "GET/POST /api/v2/tailnet/{tailnet}/devices")
    , ("DNS", "GET/POST /api/v2/tailnet/{tailnet}/dns/*")
    , ("Keys", "GET/POST /api/v2/tailnet/{tailnet}/keys")
    , ("ACL", "GET/POST /api/v2/tailnet/{tailnet}/acl")
    , ("Routes", "GET /api/v2/device/{deviceId}/routes")
    ]

  separator

  -- Show error handling
  debugStep 3 "Error Handling"

  debugSubStep "API errors are returned as structured types:"

  boxed "TailscaleError Types"
    [ "ApiError    - Server returned error response"
    , "HttpError   - HTTP-level error (timeout, etc)"
    , "JsonError   - Response parsing failed"
    , "NetworkError - Connection failed"
    ]

  debugSubStep "Example error response:"
  let mockError = ApiError $ ErrResponse
        { errStatus = 401
        , errMessage = "Invalid API key"
        }
  debugKeyValue "Error" (show mockError)

  separator

  -- Show mock device
  debugStep 4 "Example Device Response"

  debugSubStep "Device data structure:"
  debugTable
    [ ("id", "12345")
    , ("name", "my-laptop")
    , ("addresses", "[\"100.64.0.1\", \"fd7a:...\"]")
    , ("os", "linux")
    , ("hostname", "my-laptop")
    , ("clientVersion", "1.50.0")
    , ("authorized", "true")
    , ("isExternal", "false")
    , ("machineKey", "mkey:abc123...")
    , ("nodeKey", "nodekey:xyz789...")
    ]

  separator

  debugSection "Setup Instructions"

  debugInfo "To run with real API access:"
  debugInfo ""
  debugInfo "1. Get an API key from: https://login.tailscale.com/admin/settings/keys"
  debugInfo "2. Set environment variables:"
  debugInfo "   export TAILSCALE_API_KEY='tskey-api-...'"
  debugInfo "   export TAILSCALE_TAILNET='your-tailnet.ts.net'"
  debugInfo "3. Re-run this example"
  debugInfo ""

  debugSuccess "Mock demo completed!"
