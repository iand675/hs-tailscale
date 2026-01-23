{- |
Embedded Tailscale Example

This example demonstrates using the pure Haskell tsnet implementation:
- Creating an embedded Tailscale instance
- Connecting to a tailnet
- Listening for connections
- Dialing other nodes

Run with: cabal run embedded-tailscale-example

Note: Requires TAILSCALE_AUTHKEY environment variable for headless auth.
-}
module Main where

import Control.Concurrent (threadDelay)
import Control.Exception (SomeException, try)
import qualified Data.ByteString as BS
import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Environment (lookupEnv)

import Examples.Debug
import Tsnet.Embedded
import Tsnet.Control.Protocol


main :: IO ()
main = do
  debugSection "Embedded Tailscale (tsnet) Demo"

  debugInfo "The tsnet package provides a pure Haskell implementation"
  debugInfo "of Tailscale that can be embedded directly in your application."
  debugInfo "Your app will appear as a node on your tailnet."
  separator

  -- Step 1: Load Configuration
  debugStep 1 "Loading Configuration"

  debugSubStep "Reading environment variables..."
  mAuthKey <- lookupEnv "TAILSCALE_AUTHKEY"
  mHostname <- lookupEnv "TAILSCALE_HOSTNAME"

  let config = defaultConfig
        { tsHostname = T.pack $ fromMaybe "haskell-demo" mHostname
        , tsAuthKey = T.pack <$> mAuthKey
        , tsEphemeral = True  -- Auto-cleanup when we exit
        , tsLogLevel = LogDebug
        }

  debugSuccess "Configuration loaded"
  printConfig config

  separator

  -- Step 2: Create Tailscale Instance
  debugStep 2 "Creating Tailscale Instance"

  debugSubStep "Generating cryptographic keys..."
  ts <- timed "Create Tailscale instance" $ newTailscale config

  debugSuccess "Tailscale instance created"
  debugSubStep "Key information:"
  debugKeyValue "WireGuard Public Key" (show $ tsPublicKey ts)
  debugKeyValue "Node Key" (show $ tsNodeKey ts)
  debugKeyValue "Machine Key" (show $ tsMachineKey ts)

  separator

  -- Step 3: Start Connection
  debugStep 3 "Starting Tailscale Connection"

  case mAuthKey of
    Nothing -> do
      debugWarning "No TAILSCALE_AUTHKEY set - running in demo mode"
      runDemoMode ts config
    Just _ -> do
      debugSubStep "Connecting to control plane..."
      debugKeyValue "Control URL" (T.unpack $ tsControlURL config)

      startResult <- timed "Start Tailscale" $ start ts
      case startResult of
        Left (TailscaleAuthRequired authUrl) -> do
          debugWarning "Authentication required!"
          debugInfo "Please visit this URL to authenticate:"
          debugInfo $ "  " ++ T.unpack authUrl
          debugInfo ""
          debugInfo "After authenticating, set TAILSCALE_AUTHKEY and re-run."
          stop ts

        Left err -> do
          debugError $ "Failed to start: " ++ show err
          stop ts

        Right () -> do
          debugSuccess "Connected to tailnet!"
          runConnectedMode ts


-- | Run in demo mode (no real connection)
runDemoMode :: Tailscale -> Config -> IO ()
runDemoMode ts config = do
  separator
  debugSection "Demo Mode (No Auth Key)"

  debugInfo "Without an auth key, we can demonstrate the structure"
  debugInfo "of the embedded Tailscale implementation."
  separator

  -- Show configuration
  debugStep 4 "Configuration Options"

  boxed "Config Fields"
    [ "tsHostname    - Name for this node on the tailnet"
    , "tsAuthKey     - Pre-authentication key (headless)"
    , "tsEphemeral   - Auto-delete when offline"
    , "tsControlURL  - Control plane URL"
    , "tsStateDir    - Directory for persistent state"
    , "tsLogLevel    - Logging verbosity"
    ]

  separator

  -- Show lifecycle
  debugStep 5 "Lifecycle Management"

  debugSubStep "Available lifecycle functions:"
  debugTable
    [ ("newTailscale", "Create new instance (not connected)")
    , ("start", "Connect to tailnet")
    , ("stop", "Disconnect and cleanup")
    , ("withTailscale", "Bracket for safe resource management")
    ]

  separator

  -- Show networking
  debugStep 6 "Networking Operations"

  debugSubStep "Server operations:"
  debugTable
    [ ("listen", "Listen on a port (plain)")
    , ("listenTLS", "Listen with auto-TLS")
    , ("accept", "Accept incoming connection")
    ]

  debugSubStep "Client operations:"
  debugTable
    [ ("dial", "Connect to a peer")
    , ("send", "Send data on connection")
    , ("recv", "Receive data from connection")
    , ("close", "Close connection")
    ]

  separator

  -- Show information queries
  debugStep 7 "Information Queries"

  debugSubStep "Available queries:"
  debugTable
    [ ("tailscaleIPs", "Get assigned IPv4/IPv6 addresses")
    , ("certDomains", "Get available HTTPS domains")
    , ("isConnected", "Check connection status")
    , ("selfInfo", "Get this node's PeerInfo")
    ]

  separator

  debugSection "Usage Example"

  debugLn $ unlines
    [ "import Tsnet.Embedded"
    , ""
    , "main :: IO ()"
    , "main = do"
    , "  ts <- newTailscale defaultConfig"
    , "    { tsHostname = \"my-service\""
    , "    , tsAuthKey = Just \"tskey-auth-...\""
    , "    }"
    , ""
    , "  result <- start ts"
    , "  case result of"
    , "    Left err -> print err"
    , "    Right () -> do"
    , "      (ipv4, ipv6) <- tailscaleIPs ts"
    , "      print $ \"Connected: \" ++ show ipv4"
    , ""
    , "      -- Listen for connections"
    , "      Right ln <- listen ts \"tcp\" 8080"
    , "      conn <- accept ln"
    , ""
    , "      -- Handle connection..."
    , "      Right msg <- recv conn 1024"
    , "      send conn \"Hello!\""
    , "      close conn"
    , ""
    , "      stop ts"
    ]

  separator

  debugSection "Setup Instructions"

  debugInfo "To run with real Tailscale connection:"
  debugInfo ""
  debugInfo "1. Create an auth key at:"
  debugInfo "   https://login.tailscale.com/admin/settings/keys"
  debugInfo ""
  debugInfo "2. Set environment variables:"
  debugInfo "   export TAILSCALE_AUTHKEY='tskey-auth-...'"
  debugInfo "   export TAILSCALE_HOSTNAME='my-haskell-app'"
  debugInfo ""
  debugInfo "3. Re-run this example"
  debugInfo ""

  debugSuccess "Demo mode completed!"


-- | Run in connected mode
runConnectedMode :: Tailscale -> IO ()
runConnectedMode ts = do
  separator

  -- Step 4: Get Network Info
  debugStep 4 "Retrieving Network Information"

  debugSubStep "Getting assigned IPs..."
  (mIPv4, mIPv6) <- tailscaleIPs ts

  case mIPv4 of
    Nothing -> debugWarning "No IPv4 assigned"
    Just ip -> debugSuccess $ "IPv4: " ++ T.unpack ip

  case mIPv6 of
    Nothing -> debugWarning "No IPv6 assigned"
    Just ip -> debugSuccess $ "IPv6: " ++ T.unpack ip

  debugSubStep "Getting certificate domains..."
  domains <- certDomains ts
  if null domains
    then debugInfo "No HTTPS domains available"
    else mapM_ (\d -> debugKeyValue "Domain" (T.unpack d)) domains

  debugSubStep "Getting self info..."
  mSelf <- selfInfo ts
  case mSelf of
    Nothing -> debugWarning "Self info not available"
    Just self -> do
      debugSuccess "Self information retrieved"
      printPeerInfo self

  separator

  -- Step 5: Demonstrate Listening
  debugStep 5 "Setting Up Listener"

  debugSubStep "Creating TCP listener on port 8080..."
  listenResult <- listen ts "tcp" 8080
  case listenResult of
    Left err -> debugError $ "Failed to listen: " ++ show err
    Right ln -> do
      debugSuccess "Listener created on port 8080"
      debugKeyValue "Port" (show $ lnPort ln)
      debugKeyValue "TLS" (show $ lnTLS ln)

  separator

  -- Step 6: Cleanup
  debugStep 6 "Cleanup"

  debugSubStep "Stopping Tailscale..."
  stop ts
  debugSuccess "Tailscale stopped"

  separator

  debugSection "Connection Demo Complete"

  boxed "Embedded Tailscale Features"
    [ "✓ Pure Haskell implementation"
    , "✓ No external daemon required"
    , "✓ Automatic key management"
    , "✓ DERP relay support"
    , "✓ Network map synchronization"
    , "✓ Ephemeral node support"
    ]

  debugSuccess "Embedded Tailscale example completed!"


-- | Print configuration
printConfig :: Config -> IO ()
printConfig config = do
  debugTable
    [ ("Hostname", T.unpack $ tsHostname config)
    , ("Auth Key", if isNothing (tsAuthKey config) then "Not set" else "Set (hidden)")
    , ("Ephemeral", show $ tsEphemeral config)
    , ("Control URL", T.unpack $ tsControlURL config)
    , ("State Dir", maybe "None" id $ tsStateDir config)
    , ("Log Level", show $ tsLogLevel config)
    ]
  where
    isNothing Nothing = True
    isNothing _ = False


-- | Print peer info
printPeerInfo :: PeerInfo -> IO ()
printPeerInfo peer = do
  debugTable
    [ ("ID", show $ piID peer)
    , ("Name", T.unpack $ piName peer)
    , ("Stable ID", T.unpack $ piStableID peer)
    , ("Addresses", show $ piAddresses peer)
    , ("DERP", maybe "None" T.unpack $ piDERP peer)
    , ("Online", maybe "Unknown" show $ piOnline peer)
    , ("Authorized", show $ piMachineAuthorized peer)
    ]
