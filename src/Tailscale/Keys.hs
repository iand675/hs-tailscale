{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- |
-- Module      : Tailscale.Keys
-- Description : Auth key management API
-- License     : BSD-3-Clause
--
-- This module provides functions for managing authentication keys
-- in a Tailscale network.
module Tailscale.Keys
  ( -- * Listing Keys
    getKeys
  , getKey

    -- * Key Management
  , createKey
  , createKeyWithExpiry
  , deleteKey

    -- * Helper Functions
  , mkReusableKey
  , mkEphemeralKey
  , mkPreauthorizedKey
  ) where

import Data.Aeson (FromJSON, eitherDecode, encode, object, (.:), (.:?), (.=), withObject)
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (NominalDiffTime)
import Network.HTTP.Client (Request (..), parseRequest)
import Network.HTTP.Types.Header (hContentType)

import Tailscale.Client
import Tailscale.Types

-- | Get all auth key IDs for the tailnet
--
-- @
-- keyIds <- getKeys client
-- @
getKeys :: Client -> IO (Either TailscaleError [Text])
getKeys client = do
  let url = buildTailnetURL client ["keys"]
  req <- parseRequest $ T.unpack url
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right body -> case eitherDecode body of
      Left e -> pure $ Left $ JsonError $ T.pack e
      Right (KeysWrapper keys) -> pure $ Right keys

-- | Wrapper for keys list response
newtype KeysWrapper = KeysWrapper [Text]

instance FromJSON KeysWrapper where
  parseJSON = withObject "KeysWrapper" $ \o ->
    KeysWrapper <$> o .: "keys"

-- | Get details about a specific auth key
--
-- @
-- key <- getKey client "key-id-123"
-- @
getKey :: Client -> Text -> IO (Either TailscaleError Key)
getKey client keyId = do
  let url = buildTailnetURL client ["keys", keyId]
  req <- parseRequest $ T.unpack url
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Create a new auth key with default expiry (90 days)
--
-- @
-- (secret, keyMeta) <- createKey client (mkReusableKey ["tag:server"])
-- @
createKey :: Client -> KeyCapabilities -> IO (Either TailscaleError (Text, Key))
createKey client caps = do
  let url = buildTailnetURL client ["keys"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["capabilities" .= caps]
      req = baseReq
        { method = "POST"
        , requestBody = RequestBodyLBS $ encode body
        , requestHeaders = [(hContentType, "application/json")]
        }
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right respBody -> case eitherDecode respBody of
      Left e -> pure $ Left $ JsonError $ T.pack e
      Right kr -> pure $ Right (kcrKey kr, kcrMeta kr)

-- | Create a new auth key with custom expiry
--
-- @
-- (secret, keyMeta) <- createKeyWithExpiry client (mkReusableKey ["tag:server"]) (7 * 24 * 3600)
-- @
createKeyWithExpiry :: Client -> KeyCapabilities -> NominalDiffTime -> IO (Either TailscaleError (Text, Key))
createKeyWithExpiry client caps expiry = do
  let url = buildTailnetURL client ["keys"]
  baseReq <- parseRequest $ T.unpack url
  let expirySeconds = floor expiry :: Int
      body = object
        [ "capabilities" .= caps
        , "expirySeconds" .= expirySeconds
        ]
      req = baseReq
        { method = "POST"
        , requestBody = RequestBodyLBS $ encode body
        , requestHeaders = [(hContentType, "application/json")]
        }
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right respBody -> case eitherDecode respBody of
      Left e -> pure $ Left $ JsonError $ T.pack e
      Right kr -> pure $ Right (kcrKey kr, kcrMeta kr)

-- | Key creation response (includes the secret key)
data KeyCreateResponse = KeyCreateResponse
  { kcrKey  :: !Text
  , kcrMeta :: !Key
  }

instance FromJSON KeyCreateResponse where
  parseJSON = withObject "KeyCreateResponse" $ \o -> do
    key <- o .: "key"
    keyId <- o .: "id"
    created <- o .: "created"
    expires <- o .: "expires"
    caps <- o .: "capabilities"
    desc <- o .:? "description"
    pure KeyCreateResponse
      { kcrKey = key
      , kcrMeta = Key
          { keyId = keyId
          , keyCreated = created
          , keyExpires = expires
          , keyCapabilities = caps
          , keyDescription = desc
          }
      }

-- | Delete an auth key
--
-- @
-- result <- deleteKey client "key-id-123"
-- @
deleteKey :: Client -> Text -> IO (Either TailscaleError ())
deleteKey client keyId = do
  let url = buildTailnetURL client ["keys", keyId]
  baseReq <- parseRequest $ T.unpack url
  let req = baseReq { method = "DELETE" }
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right _ -> pure $ Right ()

-- | Create capabilities for a reusable key
--
-- @
-- caps = mkReusableKey ["tag:server", "tag:prod"]
-- @
mkReusableKey :: [Text] -> KeyCapabilities
mkReusableKey tags = KeyCapabilities
  { kcDevices = Just KeyDeviceCapabilities
      { kdcCreate = KeyDeviceCreateCapabilities
          { kdccReusable = True
          , kdccEphemeral = False
          , kdccPreauthorized = False
          , kdccTags = if null tags then Nothing else Just tags
          }
      }
  }

-- | Create capabilities for an ephemeral key
--
-- @
-- caps = mkEphemeralKey ["tag:temp"]
-- @
mkEphemeralKey :: [Text] -> KeyCapabilities
mkEphemeralKey tags = KeyCapabilities
  { kcDevices = Just KeyDeviceCapabilities
      { kdcCreate = KeyDeviceCreateCapabilities
          { kdccReusable = False
          , kdccEphemeral = True
          , kdccPreauthorized = False
          , kdccTags = if null tags then Nothing else Just tags
          }
      }
  }

-- | Create capabilities for a preauthorized key
--
-- @
-- caps = mkPreauthorizedKey ["tag:trusted"]
-- @
mkPreauthorizedKey :: [Text] -> KeyCapabilities
mkPreauthorizedKey tags = KeyCapabilities
  { kcDevices = Just KeyDeviceCapabilities
      { kdcCreate = KeyDeviceCreateCapabilities
          { kdccReusable = False
          , kdccEphemeral = False
          , kdccPreauthorized = True
          , kdccTags = if null tags then Nothing else Just tags
          }
      }
  }

-- | Parse a JSON response into the expected type
parseJsonResponse :: FromJSON a => Either TailscaleError LBS.ByteString -> Either TailscaleError a
parseJsonResponse (Left err) = Left err
parseJsonResponse (Right body) =
  case eitherDecode body of
    Left e -> Left $ JsonError $ T.pack e
    Right a -> Right a
