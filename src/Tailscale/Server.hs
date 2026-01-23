{- |
Module      : Tailscale.Server
Description : Utilities for running servers on Tailscale
License     : BSD-3-Clause

This module re-exports server utilities from @tsnet@.
See "Tsnet.Server" for full documentation.
-}
module Tailscale.Server (
  -- * Server Configuration
  TailscaleServerConfig (..),
  getTailscaleServerConfig,
  getTailscaleServerConfigWith,

  -- * TLS Configuration
  TailscaleTLSConfig (..),
  getTailscaleTLSConfig,
  writeTLSCredentials,

  -- * Caller Identification
  CallerInfo (..),
  identifyCallerByAddr,

  -- * Address Utilities
  tailscaleIPv4,
  tailscaleIPv6,
  isIPv4,
  isIPv6,
) where

import Tsnet.Server
