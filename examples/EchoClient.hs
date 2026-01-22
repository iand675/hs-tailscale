{-# LANGUAGE OverloadedStrings #-}

-- | Example echo client using Tailscale networking
module Main where

import Network.Tailscale
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO

main :: IO ()
main = do
  putStrLn "=== Tailscale Echo Client Example ==="
  putStrLn ""
  putStrLn "This example demonstrates how to create a simple client that"
  putStrLn "connects to peers on the Tailscale network."
  putStrLn ""
  
  -- Load configuration
  config <- loadConfig
  putStrLn $ "Loaded configuration from: " ++ configStatePath config
  
  -- Create a Tailscale client
  client <- newClient config
  putStrLn "Created Tailscale client"
  
  -- In a real application, you would:
  -- 1. Get an auth key from the Tailscale admin console
  -- 2. Authenticate with the control plane
  -- 3. Connect to the Tailscale network
  -- 4. Discover peers
  -- 5. Dial connections to peers
  
  putStrLn ""
  putStrLn "To use this in production, you would need to:"
  putStrLn "1. Obtain an auth key from https://login.tailscale.com/admin/settings/keys"
  putStrLn "2. Set the auth key in the configuration"
  putStrLn "3. Call authenticate and connectClient"
  putStrLn "4. Use listPeers to discover available peers"
  putStrLn "5. Use the dialer to connect to a peer"
  putStrLn ""
  
  -- Example connection flow (commented out as it requires a real auth key)
  {-
  let authKey = AuthKey "tskey-your-auth-key-here"
  authResult <- authenticate authKey
  case authResult of
    Right token -> do
      connectClient client token
      putStrLn "Connected to Tailscale network"
      
      -- List available peers
      peers <- listPeers client
      putStrLn $ "Found " ++ show (length peers) ++ " peers"
      
      -- Connect to the first peer
      case peers of
        (peer:_) -> do
          let dialerConfig = defaultDialerConfig
          dialer <- newDialer client dialerConfig
          conn <- dialPeer dialer (peerID peer) (Port 8080)
          putStrLn $ "Connected to peer: " ++ show (peerName peer)
          -- Send and receive data
          closeConnection conn
        [] -> putStrLn "No peers available"
      
      disconnectClient client
      
    Left err -> do
      putStrLn $ "Authentication failed: " ++ T.unpack err
      exitFailure
  -}
  
  putStrLn "Example completed. This is a demonstration of the API structure."
  putStrLn "A full implementation would require integration with Tailscale's control plane."
