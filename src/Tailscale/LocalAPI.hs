{- |
Module      : Tailscale.LocalAPI
Description : Client for the Tailscale LocalAPI (tailscaled daemon)
License     : BSD-3-Clause

This module re-exports the LocalAPI client functionality from @tsnet@.
See "Tsnet.LocalAPI" for full documentation.
-}
module Tailscale.LocalAPI (
  -- * Client
  LocalClient (..),
  newLocalClient,
  newLocalClientWithSocket,

  -- * Status
  getStatus,
  getStatusWithoutPeers,

  -- * Identity
  whoIs,
  whoIsNodeKey,

  -- * Certificates
  getCertPair,
  expandSNIName,

  -- * Preferences
  getPrefs,

  -- * Ping
  ping,

  -- * Serve Configuration
  getServeConfig,
  setServeConfig,

  -- * Network Lock
  getNetworkLockStatus,

  -- * File Transfer
  getWaitingFiles,
  getFileTargets,

  -- * Utilities
  getTailscaleIPs,
  getCertDomains,
  isRunning,

  -- * Re-exports
  module Tailscale.LocalAPI.Types,
) where

import Tailscale.LocalAPI.Types
import Tsnet.LocalAPI
