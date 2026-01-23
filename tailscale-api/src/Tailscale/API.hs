{- |
Module      : Tailscale.API
Description : Haskell client for the Tailscale REST API
License     : BSD-3-Clause

This is a Haskell client for the Tailscale control plane API, providing
functions for managing devices, DNS settings, ACLs, authentication keys,
and routes.

= Quick Start

@
import Tailscale.API

main :: IO ()
main = do
  client <- newClient "your-tailnet.com" (APIKey "tskey-api-...")
  result <- getDevices client Nothing
  case result of
    Left err -> print err
    Right devices -> mapM_ (print . deviceName) devices
@

= Authentication

The Tailscale API uses API keys for authentication. Create an API key at:
<https://login.tailscale.com/admin/settings/keys>
-}
module Tailscale.API (
  -- * Client
  Client,
  newClient,
  defaultClient,

  -- * Authentication
  AuthMethod (..),
  APIKey (..),

  -- * Error Handling
  TailscaleError (..),
  ErrResponse (..),

  -- * Device API
  Device (..),
  ClientConnectivity (..),
  DerpRegion (..),
  DevicePostureIdentity (..),
  DeviceFieldsOpts,
  deviceAllFields,
  deviceDefaultFields,
  getDevices,
  getDevice,
  deleteDevice,
  authorizeDevice,
  setAuthorized,
  setTags,

  -- * DNS API
  DNSConfig (..),
  DNSNameServers (..),
  DNSNameServersPostResponse (..),
  DNSSearchPaths (..),
  DNSPreferences (..),
  getDNSConfig,
  setDNSConfig,
  getNameServers,
  setNameServers,
  getDNSPreferences,
  setDNSPreferences,
  getSearchPaths,
  setSearchPaths,

  -- * Keys API
  Key (..),
  KeyCapabilities (..),
  KeyDeviceCapabilities (..),
  KeyDeviceCreateCapabilities (..),
  getKeys,
  getKey,
  createKey,
  createKeyWithExpiry,
  deleteKey,
  mkReusableKey,
  mkEphemeralKey,
  mkPreauthorizedKey,

  -- * ACL API
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
  getACL,
  getACLHuJSON,
  setACL,
  setACLHuJSON,
  previewACLForUser,
  previewACLForIPPort,
  previewACLHuJSONForUser,
  previewACLHuJSONForIPPort,
  validateACLJSON,

  -- * Routes API
  Routes (..),
  getRoutes,
  setRoutes,

  -- * Tailnet API
  deleteTailnet,
) where

import Tailscale.API.ACL
import Tailscale.API.Client
import Tailscale.API.DNS
import Tailscale.API.Device
import Tailscale.API.Keys
import Tailscale.API.Routes
import Tailscale.API.Tailnet
import Tailscale.API.Types
