{-# LANGUAGE OverloadedStrings #-}

-- | Example echo server using Tailscale networking
module Main where

import Network.Tailscale
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO

main :: IO ()
main = do
  putStrLn "=== Tailscale Echo Server Example ==="
  putStrLn ""
  putStrLn "This example demonstrates how to create a simple echo server"
  putStrLn "that listens for connections on the Tailscale network."
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
  
  putStrLn ""
  putStrLn "To use this in production, you would need to:"
  putStrLn "1. Obtain an auth key from https://login.tailscale.com/admin/settings/keys"
  putStrLn "2. Set the auth key in the configuration"
  putStrLn "3. Call authenticate and connectClient"
  putStrLn ""
  
  -- Example authentication flow (commented out as it requires a real auth key)
  {-
  let authKey = AuthKey "tskey-your-auth-key-here"
  authResult <- authenticate authKey
  case authResult of
    Right token -> do
      connectClient client token
      putStrLn "Connected to Tailscale network"
      
      -- Create and start a listener
      let listenerConfig = defaultListenerConfig (Port 8080)
      listener <- newListener client listenerConfig
      listen listener
      putStrLn "Listening on port 8080"
      
      -- Accept connections in a loop
      forever $ do
        conn <- accept listener
        putStrLn $ "Accepted connection from: " ++ show (connPeer conn)
        -- Handle the connection (echo data back)
        
    Left err -> do
      putStrLn $ "Authentication failed: " ++ T.unpack err
      exitFailure
  -}
  
  putStrLn "Example completed. This is a demonstration of the API structure."
  putStrLn "A full implementation would require integration with Tailscale's control plane."
