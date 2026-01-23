{- |
Module      : Tailscale.Embedded
Description : Pure Haskell embedded Tailscale implementation
License     : BSD-3-Clause

This module re-exports embedded Tailscale functionality from @tsnet@.
See "Tsnet.Embedded" for full documentation.
-}
module Tailscale.Embedded (
  -- * Tailscale Instance
  Tailscale,
  Config (..),
  defaultConfig,

  -- * Lifecycle
  newTailscale,
  start,
  stop,
  withTailscale,

  -- * Information
  tailscaleIPs,
  certDomains,
  isConnected,
  selfInfo,

  -- * Networking
  Listener,
  Connection,
  listen,
  listenTLS,
  accept,
  dial,
  send,
  recv,
  close,
  localAddr,
  remoteAddr,

  -- * Errors
  TailscaleError (..),

  -- * Re-exports
  PeerInfo (..),
  NetworkMap (..),
) where

import Tsnet.Embedded
