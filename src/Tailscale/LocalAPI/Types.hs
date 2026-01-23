{- |
Module      : Tailscale.LocalAPI.Types
Description : Types for the Tailscale LocalAPI
License     : BSD-3-Clause

This module re-exports types for the LocalAPI from @tsnet@.
-}
module Tailscale.LocalAPI.Types (
  -- * Status Types
  Status (..),
  PeerStatus (..),
  TailscaleIP (..),
  BackendState (..),

  -- * WhoIs Types
  WhoIsResponse (..),
  Node (..),
  UserProfile (..),
  CapabilityMap (..),

  -- * Certificate Types
  CertPair (..),

  -- * Preferences
  Prefs (..),

  -- * Ping Types
  PingResult (..),
  PingType (..),

  -- * File Transfer Types
  WaitingFile (..),
  FileTarget (..),

  -- * Serve Config Types
  ServeConfig (..),
  ServeConfigHandler (..),

  -- * Network Lock Types
  NetworkLockStatus (..),

  -- * Error Types
  LocalAPIError (..),
) where

import Tsnet.LocalAPI.Types
