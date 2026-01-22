{-# LANGUAGE OverloadedStrings #-}

-- | Authentication with Tailscale control plane
module Network.Tailscale.Auth
  ( -- * Authentication
    authenticate
  , registerDevice
  , renewToken
    -- * Key Management
  , generateDeviceKey
  ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import Network.Tailscale.Types
  ( AuthKey(..)
  , DeviceKey(..)
  , AuthToken(..)
  , NodeKey(..)
  )

-- | Authenticate with the Tailscale control plane
-- In a real implementation, this would make HTTP requests to the control plane
authenticate :: AuthKey -> IO (Either Text AuthToken)
authenticate (AuthKey key) = do
  -- Placeholder implementation
  -- A real implementation would:
  -- 1. Make an HTTP request to the control plane
  -- 2. Exchange the auth key for an access token
  -- 3. Handle OAuth flows if needed
  return $ Right (AuthToken ("authenticated-with-" <> key))

-- | Register a new device with the control plane
registerDevice :: AuthKey -> NodeKey -> Text -> IO (Either Text AuthToken)
registerDevice authKey _nodeKey hostname = do
  -- Placeholder implementation
  -- A real implementation would:
  -- 1. Generate or load device keys
  -- 2. Register with the control plane
  -- 3. Return authentication token
  result <- authenticate authKey
  case result of
    Right token -> return $ Right token
    Left err -> return $ Left ("Device registration failed: " <> err <> " for host " <> hostname)

-- | Renew an authentication token
renewToken :: AuthToken -> IO (Either Text AuthToken)
renewToken (AuthToken token) = do
  -- Placeholder implementation
  -- A real implementation would make an HTTP request to refresh the token
  return $ Right (AuthToken ("renewed-" <> token))

-- | Generate a new device key
generateDeviceKey :: IO DeviceKey
generateDeviceKey = do
  -- Placeholder implementation
  -- A real implementation would use proper cryptographic key generation
  -- For now, we generate a simple placeholder
  let dummyKey = BS.pack [0..31]  -- 32-byte key
  return $ DeviceKey dummyKey
