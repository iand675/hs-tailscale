{-# LANGUAGE OverloadedStrings #-}

-- | Haskell bindings for Tailscale networking
--
-- This library provides a Haskell interface for building standalone Tailscale
-- services, enabling peer-to-peer connections and mesh networking capabilities.
--
-- = Quick Start
--
-- To create a simple Tailscale service:
--
-- @
-- import Network.Tailscale
--
-- main :: IO ()
-- main = do
--   -- Load configuration
--   config <- loadConfig
--   
--   -- Create a client
--   client <- newClient config
--   
--   -- Authenticate (you'll need an auth key from Tailscale)
--   authResult <- authenticate (AuthKey "your-auth-key")
--   case authResult of
--     Right token -> do
--       -- Connect to Tailscale network
--       connectClient client token
--       
--       -- Create a listener
--       let lConfig = defaultListenerConfig (Port 8080)
--       listener <- newListener client lConfig
--       listen listener
--       
--       -- Accept connections
--       conn <- accept listener
--       print conn
--     Left err -> putStrLn $ "Authentication failed: " ++ show err
-- @
--
-- = Core Concepts
--
-- * 'Client': Represents a connection to the Tailscale control plane
-- * 'Listener': Accepts incoming connections from peers
-- * 'Dialer': Establishes outgoing connections to peers
-- * 'Node': Represents this device on the Tailscale network
-- * 'Peer': Represents another device on the network
--
module Network.Tailscale
  ( -- * Client Operations
    module Network.Tailscale.Client
    -- * Configuration
  , module Network.Tailscale.Config
    -- * Authentication
  , module Network.Tailscale.Auth
    -- * Network Operations
  , module Network.Tailscale.Listener
  , module Network.Tailscale.Dialer
    -- * Types
  , module Network.Tailscale.Types
  ) where

import Network.Tailscale.Client
import Network.Tailscale.Config
import Network.Tailscale.Auth
import Network.Tailscale.Listener
import Network.Tailscale.Dialer
import Network.Tailscale.Types
