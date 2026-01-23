{- |
Module      : Tsnet
Description : Pure Haskell embedded Tailscale networking
License     : BSD-3-Clause

This module provides a pure Haskell implementation of embedded Tailscale
networking, similar to Go's tsnet package. This allows Haskell applications
to join a Tailscale network without requiring the tailscaled daemon.

= Overview

The tsnet package provides two main ways to use Tailscale:

1. __Embedded Tailscale__ ('Tsnet.Embedded'): A pure Haskell implementation
   that embeds Tailscale directly in your application. Your app appears as
   a node on the tailnet without needing the tailscaled daemon.

2. __LocalAPI Client__ ('Tsnet.LocalAPI'): Communication with a running
   tailscaled daemon for status, certificates, and identity verification.

= Quick Start: Embedded Mode

@
import Tsnet
import Tsnet.Embedded

main :: IO ()
main = do
  ts <- newTailscale defaultConfig
    { tsHostname = \"my-app\"
    , tsAuthKey = Just \"tskey-auth-...\"
    }

  result <- start ts
  case result of
    Left err -> error $ show err
    Right () -> do
      (ipv4, ipv6) <- tailscaleIPs ts
      putStrLn $ \"Connected: \" <> show ipv4

      -- Listen for connections
      listener <- listen ts \"tcp\" 8080
      -- ...
@

= Quick Start: LocalAPI Mode

@
import Tsnet
import Tsnet.LocalAPI

main :: IO ()
main = do
  client <- newLocalClient

  status <- getStatus client
  case status of
    Left err -> print err
    Right s -> print $ statusBackendState s

  -- Identify incoming connections
  caller <- whoIs client \"100.64.1.2\"
  -- ...
@

= Package Structure

* "Tsnet.Embedded" - Embedded Tailscale client
* "Tsnet.LocalAPI" - LocalAPI client for tailscaled
* "Tsnet.Server" - Server utilities (TLS certs, caller identification)
* "Tsnet.Control.Protocol" - Control plane protocol types
* "Tsnet.Control.Client" - Control plane client
* "Tsnet.DERP.Protocol" - DERP relay protocol
* "Tsnet.DERP.Client" - DERP relay client
* "Tsnet.Network.Packet" - IP packet handling
-}
module Tsnet (
  -- * Embedded Tailscale
  -- $embedded
  module Tsnet.Embedded,

  -- * LocalAPI Client
  -- $localapi
  module Tsnet.LocalAPI,

  -- * Server Utilities
  -- $server
  module Tsnet.Server,
) where

import Tsnet.Embedded
import Tsnet.LocalAPI
import Tsnet.Server

-- $embedded
--
-- The 'Tsnet.Embedded' module provides a pure Haskell implementation of
-- Tailscale that runs entirely within your application. This is similar to
-- Go's tsnet package.
--
-- Key types and functions:
--
-- * 'Tailscale' - The embedded Tailscale instance
-- * 'newTailscale' - Create a new instance
-- * 'start' / 'stop' - Lifecycle management
-- * 'listen' / 'dial' - Network connections
-- * 'tailscaleIPs' - Get assigned IP addresses

-- $localapi
--
-- The 'Tsnet.LocalAPI' module provides a client for communicating with
-- a running tailscaled daemon. Use this when you want to leverage an
-- existing Tailscale installation.
--
-- Key types and functions:
--
-- * 'LocalClient' - Client for the LocalAPI
-- * 'getStatus' - Get daemon status
-- * 'whoIs' - Identify connections
-- * 'getCertPair' - Get TLS certificates

-- $server
--
-- The 'Tsnet.Server' module provides utilities for running servers on
-- Tailscale networks with automatic TLS and caller identification.
--
-- Key types and functions:
--
-- * 'TailscaleServerConfig' - Server configuration
-- * 'getTailscaleServerConfig' - Get configuration from Tailscale
-- * 'identifyCallerByAddr' - Identify who is connecting
