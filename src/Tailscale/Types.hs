{- |
Module      : Tailscale.Types
Description : Core types for the Tailscale API
License     : BSD-3-Clause

This module re-exports all the data types used by the Tailscale API client
from the @tailscale-api@ package.
-}
module Tailscale.Types (
  -- * Error Types
  TailscaleError (..),
  ErrResponse (..),

  -- * Device Types
  Device (..),
  ClientConnectivity (..),
  DerpRegion (..),
  DevicePostureIdentity (..),
  DeviceFieldsOpts (..),
  deviceAllFields,
  deviceDefaultFields,

  -- * DNS Types
  DNSConfig (..),
  DNSNameServers (..),
  DNSNameServersPostResponse (..),
  DNSSearchPaths (..),
  DNSPreferences (..),

  -- * Key Types
  Key (..),
  KeyCapabilities (..),
  KeyDeviceCapabilities (..),
  KeyDeviceCreateCapabilities (..),

  -- * ACL Types
  ACL (..),
  ACLDetails (..),
  ACLRow (..),
  ACLTest (..),
  NodeAttrGrant (..),
  ACLHuJSON (..),
  ACLTestError (..),
  ACLTestFailureSummary (..),
  ACLPreview (..),
  UserRuleMatch (..),

  -- * Routes Types
  Routes (..),
) where

import Tailscale.API.Types
