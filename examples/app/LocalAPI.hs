{- |
Tailscale LocalAPI Example

This example demonstrates using the Tailscale LocalAPI client to:
- Get tailscaled daemon status
- Identify connecting clients (WhoIs)
- Retrieve TLS certificates
- Check Tailscale preferences

Run with: cabal run local-api-example

Note: Requires tailscaled daemon to be running on the local machine.
-}
module Main where

import Control.Exception (SomeException, try)
import Data.Maybe (fromMaybe, isJust)
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Info (os)

import Examples.Debug
import Tsnet.LocalAPI
import Tsnet.LocalAPI.Types


main :: IO ()
main = do
  debugSection "Tailscale LocalAPI Client Demo"

  debugInfo "The LocalAPI allows communication with the local tailscaled daemon"
  debugInfo "via a Unix domain socket for status queries and management."
  separator

  -- Step 1: Check Prerequisites
  debugStep 1 "Checking Prerequisites"

  let socketPath = case os of
        "darwin" -> "/var/run/tailscaled.socket"
        _ -> "/var/run/tailscale/tailscaled.sock"

  debugKeyValue "Operating System" os
  debugKeyValue "Socket Path" socketPath
  debugInfo "Attempting to connect to tailscaled..."

  separator

  -- Step 2: Create Client
  debugStep 2 "Creating LocalAPI Client"

  result <- try $ newLocalClient
  case result of
    Left (e :: SomeException) -> do
      debugError $ "Failed to create client: " ++ show e
      runMockDemo
    Right client -> do
      debugSuccess "LocalAPI client created"
      debugKeyValue "Socket" (localClientSocketPath client)
      separator

      -- Test if daemon is running
      running <- isRunning client
      if running
        then runRealDemo client
        else do
          debugWarning "tailscaled is not running or not accessible"
          runMockDemo


-- | Run demo with real daemon
runRealDemo :: LocalClient -> IO ()
runRealDemo client = do
  -- Step 3: Get Status
  debugStep 3 "Getting Tailscale Status"

  debugSubStep "Fetching status (with peers)..."
  debugInfo "GET /localapi/v0/status"

  statusResult <- timed "Fetch status" $ getStatus client
  debugEither "Status" statusResult $ \status -> do
    debugSuccess "Status retrieved successfully"
    printStatus status

  separator

  -- Step 4: Get Tailscale IPs
  debugStep 4 "Getting Tailscale IPs"

  debugSubStep "Extracting assigned IPs..."
  ipsResult <- getTailscaleIPs client
  debugEither "Tailscale IPs" ipsResult $ \ips -> do
    if null ips
      then debugWarning "No IPs assigned (not connected?)"
      else do
        debugSuccess $ "Found " ++ show (length ips) ++ " IP(s)"
        mapM_ (\ip -> debugKeyValue "IP" (T.unpack ip)) ips

  separator

  -- Step 5: Get Certificate Domains
  debugStep 5 "Getting Certificate Domains"

  debugSubStep "Checking available HTTPS domains..."
  domainsResult <- getCertDomains client
  debugEither "Cert domains" domainsResult $ \domains -> do
    if null domains
      then debugInfo "No certificate domains available (HTTPS disabled?)"
      else do
        debugSuccess $ "Found " ++ show (length domains) ++ " domain(s)"
        mapM_ (\d -> debugKeyValue "Domain" (T.unpack d)) domains

  separator

  -- Step 6: Get Preferences
  debugStep 6 "Getting Preferences"

  debugSubStep "Fetching daemon preferences..."
  debugInfo "GET /localapi/v0/prefs"

  prefsResult <- getPrefs client
  debugEither "Preferences" prefsResult $ \prefs -> do
    debugSuccess "Preferences retrieved"
    printPrefs prefs

  separator

  -- Step 7: WhoIs Example
  debugStep 7 "WhoIs Identity Lookup"

  debugInfo "The WhoIs API allows you to identify who is connecting"
  debugInfo "to your service based on their IP address."
  debugInfo ""

  -- Get our own IP to demo WhoIs
  case ipsResult of
    Right (ip:_) -> do
      debugSubStep $ "Looking up: " ++ T.unpack ip
      whoIsResult <- whoIs client ip
      debugEither "WhoIs" whoIsResult $ \whois -> do
        debugSuccess "Identity found"
        printWhoIs whois
    _ -> debugInfo "Skipping WhoIs (no IPs available)"

  separator

  -- Step 8: Network Lock Status
  debugStep 8 "Network Lock Status"

  debugSubStep "Checking Tailnet Key Authority (TKA) status..."
  debugInfo "GET /localapi/v0/tka/status"

  nlResult <- getNetworkLockStatus client
  debugEither "Network Lock" nlResult $ \nlStatus -> do
    debugSuccess "Network lock status retrieved"
    debugKeyValue "Enabled" (show $ nlsEnabled nlStatus)
    debugKeyValue "Node Key Trusted" (show $ nlsNodeKeySigned nlStatus)

  separator

  -- Summary
  debugSection "LocalAPI Demo Complete"

  boxed "LocalAPI Capabilities"
    [ "✓ Status and peer information"
    , "✓ TLS certificate provisioning"
    , "✓ Identity verification (WhoIs)"
    , "✓ Preference management"
    , "✓ File transfer coordination"
    , "✓ Network lock (TKA) status"
    , "✓ Serve configuration"
    ]

  debugSuccess "LocalAPI example completed!"


-- | Print status information
printStatus :: Status -> IO ()
printStatus status = do
  debugSubStep "Backend state:"
  debugKeyValue "State" (show $ statusBackendState status)
  debugKeyValue "Version" (T.unpack $ fromMaybe "Unknown" $ statusVersion status)

  case statusSelf status of
    Nothing -> debugInfo "No self node information"
    Just self -> do
      debugSubStep "This node:"
      debugTable
        [ ("Name", T.unpack $ psName self)
        , ("DNS Name", T.unpack $ fromMaybe "" $ psDNSName self)
        , ("Online", show $ fromMaybe False $ psOnline self)
        , ("Active", show $ fromMaybe False $ psActive self)
        ]

  case statusPeer status of
    Nothing -> debugInfo "No peer information"
    Just peers | Map.null peers -> debugInfo "No peers connected"
    Just peers -> do
      debugSubStep $ "Peers (" ++ show (Map.size peers) ++ "):"
      mapM_ printPeer (take 5 $ Map.toList peers)
      when (Map.size peers > 5) $
        debugInfo $ "... and " ++ show (Map.size peers - 5) ++ " more"


-- | Print peer information
printPeer :: (T.Text, PeerStatus) -> IO ()
printPeer (key, peer) = do
  let name = T.unpack $ psName peer
      online = if fromMaybe False (psOnline peer) then "Online" else "Offline"
  debugKeyValue ("  " ++ take 20 name) online


-- | Print preferences
printPrefs :: Prefs -> IO ()
printPrefs prefs = do
  debugTable
    [ ("Control URL", T.unpack $ prefsControlURL prefs)
    , ("Routes All", show $ prefsRouteAll prefs)
    , ("Allow LAN Access", show $ prefsAllowSingleHosts prefs)
    , ("Shield Mode", show $ prefsShieldsUp prefs)
    , ("Exit Node", maybe "None" T.unpack $ prefsExitNodeID prefs)
    ]


-- | Print WhoIs information
printWhoIs :: WhoIsResponse -> IO ()
printWhoIs whois = do
  debugSubStep "Node information:"
  case whoIsNode whois of
    Nothing -> debugInfo "No node information"
    Just node -> do
      debugKeyValue "Node ID" (show $ wnID node)
      debugKeyValue "Name" (T.unpack $ wnName node)
      debugKeyValue "Stable ID" (T.unpack $ wnStableID node)

  debugSubStep "User profile:"
  case whoIsUserProfile whois of
    Nothing -> debugInfo "No user profile"
    Just profile -> do
      debugKeyValue "Login Name" (T.unpack $ upLoginName profile)
      debugKeyValue "Display Name" (T.unpack $ upDisplayName profile)
      case upProfilePicURL profile of
        Nothing -> return ()
        Just url -> debugKeyValue "Profile Pic" (T.unpack url)


-- | Run mock demo when daemon not available
runMockDemo :: IO ()
runMockDemo = do
  separator
  debugSection "Running Mock Demo (Daemon Not Available)"

  debugInfo "Since tailscaled is not running, we'll demonstrate"
  debugInfo "the LocalAPI structure with mock data."
  separator

  -- Show API structure
  debugStep 3 "LocalAPI Endpoints"

  debugSubStep "Available endpoints:"
  debugTable
    [ ("/localapi/v0/status", "Get current status and peers")
    , ("/localapi/v0/whois", "Identify peer by IP or key")
    , ("/localapi/v0/cert/{domain}", "Get TLS certificates")
    , ("/localapi/v0/prefs", "Get/set preferences")
    , ("/localapi/v0/serve-config", "Manage serve configuration")
    , ("/localapi/v0/tka/status", "Network lock status")
    , ("/localapi/v0/files", "File transfer status")
    , ("/localapi/v0/file-targets", "Available file targets")
    ]

  separator

  -- Show error types
  debugStep 4 "Error Handling"

  boxed "LocalAPIError Types"
    [ "LocalAPIHttpError      - HTTP error from daemon"
    , "LocalAPIJsonError      - JSON parsing error"
    , "LocalAPIConnectionError - Socket connection failed"
    , "LocalAPIAccessDenied   - Permission denied (403)"
    , "LocalAPIPreconditionsFailed - Preconditions not met"
    , "LocalAPIDaemonNotRunning - Daemon not running"
    ]

  separator

  -- Show mock status
  debugStep 5 "Example Status Response"

  debugSubStep "Status structure:"
  debugTable
    [ ("BackendState", "Running | NeedsLogin | ...")
    , ("Self", "PeerStatus of this node")
    , ("Peer", "Map of all connected peers")
    , ("User", "Map of user profiles")
    , ("TailscaleIPs", "[\"100.x.y.z\", \"fd7a:...\"]")
    , ("MagicDNSSuffix", "tail-scale.ts.net")
    , ("CertDomains", "[\"myhost.tail-scale.ts.net\"]")
    ]

  separator

  debugSection "Setup Instructions"

  debugInfo "To run with real LocalAPI access:"
  debugInfo ""
  debugInfo "1. Install Tailscale: https://tailscale.com/download"
  debugInfo "2. Start the daemon:"
  debugInfo "   sudo tailscaled"
  debugInfo "3. Authenticate:"
  debugInfo "   tailscale up"
  debugInfo "4. Re-run this example"
  debugInfo ""

  debugSuccess "Mock demo completed!"


-- Helper
when :: Bool -> IO () -> IO ()
when True action = action
when False _ = return ()
