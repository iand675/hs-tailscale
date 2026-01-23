-- |
-- Module      : Tailscale
-- Description : Haskell client for the Tailscale API
-- License     : BSD-3-Clause
--
-- This is a Haskell port of the official Tailscale Go SDK, providing
-- access to the Tailscale control plane API for managing devices, DNS
-- settings, ACLs, authentication keys, and routes.
--
-- = Quick Start
--
-- @
-- import Tailscale
--
-- main :: IO ()
-- main = do
--   -- Create a client with your API key
--   client <- newClient "your-tailnet.com" (APIKey "tskey-api-...")
--
--   -- List all devices
--   result <- getDevices client Nothing
--   case result of
--     Left err -> print err
--     Right devices -> mapM_ (print . deviceName) devices
-- @
--
-- = Authentication
--
-- The Tailscale API uses API keys for authentication. You can create
-- an API key in the Tailscale admin console at:
-- <https://login.tailscale.com/admin/settings/keys>
--
-- = API Coverage
--
-- This library covers the following Tailscale API endpoints:
--
-- * __Devices__: List, get, delete, authorize, and tag devices
-- * __DNS__: Configure nameservers, search paths, and MagicDNS
-- * __Keys__: Create and manage authentication keys
-- * __ACLs__: Read and write access control lists
-- * __Routes__: Manage subnet routes on devices
-- * __Tailnet__: Tailnet-level operations
--
module Tailscale
  ( -- * Client
    Client
  , newClient
  , defaultClient

    -- * Authentication
  , AuthMethod (..)
  , APIKey (..)

    -- * Error Handling
  , TailscaleError (..)
  , ErrResponse (..)

    -- * Device API
  , Device (..)
  , ClientConnectivity (..)
  , DerpRegion (..)
  , DevicePostureIdentity (..)
  , DeviceFieldsOpts
  , deviceAllFields
  , deviceDefaultFields
  , getDevices
  , getDevice
  , deleteDevice
  , authorizeDevice
  , setAuthorized
  , setTags

    -- * DNS API
  , DNSConfig (..)
  , DNSNameServers (..)
  , DNSNameServersPostResponse (..)
  , DNSSearchPaths (..)
  , DNSPreferences (..)
  , getDNSConfig
  , setDNSConfig
  , getNameServers
  , setNameServers
  , getDNSPreferences
  , setDNSPreferences
  , getSearchPaths
  , setSearchPaths

    -- * Keys API
  , Key (..)
  , KeyCapabilities (..)
  , KeyDeviceCapabilities (..)
  , KeyDeviceCreateCapabilities (..)
  , getKeys
  , getKey
  , createKey
  , createKeyWithExpiry
  , deleteKey
  , mkReusableKey
  , mkEphemeralKey
  , mkPreauthorizedKey

    -- * ACL API
  , ACL (..)
  , ACLDetails (..)
  , ACLRow (..)
  , ACLTest (..)
  , NodeAttrGrant (..)
  , ACLHuJSON (..)
  , ACLTestError (..)
  , ACLTestFailureSummary (..)
  , ACLPreview (..)
  , UserRuleMatch (..)
  , getACL
  , getACLHuJSON
  , setACL
  , setACLHuJSON
  , previewACLForUser
  , previewACLForIPPort
  , previewACLHuJSONForUser
  , previewACLHuJSONForIPPort
  , validateACLJSON

    -- * Routes API
  , Routes (..)
  , getRoutes
  , setRoutes

    -- * Tailnet API
  , deleteTailnet
  ) where

import Tailscale.ACL
import Tailscale.Client
import Tailscale.DNS
import Tailscale.Device
import Tailscale.Keys
import Tailscale.Routes
import Tailscale.Tailnet
import Tailscale.Types
