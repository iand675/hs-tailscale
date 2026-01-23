{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Tailscale.API.Keys
Description : Auth key management API
License     : BSD-3-Clause
-}
module Tailscale.API.Keys (
  getKeys,
  getKey,
  createKey,
  createKeyWithExpiry,
  deleteKey,
  mkReusableKey,
  mkEphemeralKey,
  mkPreauthorizedKey,
) where

import Data.Aeson (FromJSON (..), eitherDecode, encode, object, withObject, (.:), (.:?), (.=))
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (NominalDiffTime)
import Network.HTTP.Client (Request (..), RequestBody (RequestBodyLBS), parseRequest)
import Network.HTTP.Types.Header (hContentType)

import Tailscale.API.Client
import Tailscale.API.Types

-- | Get all auth key IDs for the tailnet
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

newtype KeysWrapper = KeysWrapper [Text]

instance FromJSON KeysWrapper where
  parseJSON = withObject "KeysWrapper" $ \o ->
    KeysWrapper <$> o .: "keys"

-- | Get details about a specific auth key
getKey :: Client -> Text -> IO (Either TailscaleError Key)
getKey client kid = do
  let url = buildTailnetURL client ["keys", kid]
  req <- parseRequest $ T.unpack url
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Create a new auth key with default expiry (90 days)
createKey :: Client -> KeyCapabilities -> IO (Either TailscaleError (Text, Key))
createKey client caps = do
  let url = buildTailnetURL client ["keys"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["capabilities" .= caps]
      req =
        baseReq
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
createKeyWithExpiry ::
  Client -> KeyCapabilities -> NominalDiffTime -> IO (Either TailscaleError (Text, Key))
createKeyWithExpiry client caps expiry = do
  let url = buildTailnetURL client ["keys"]
  baseReq <- parseRequest $ T.unpack url
  let expirySeconds = floor expiry :: Int
      body =
        object
          [ "capabilities" .= caps
          , "expirySeconds" .= expirySeconds
          ]
      req =
        baseReq
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

data KeyCreateResponse = KeyCreateResponse
  { kcrKey :: !Text
  , kcrMeta :: !Key
  }

instance FromJSON KeyCreateResponse where
  parseJSON = withObject "KeyCreateResponse" $ \o -> do
    key <- o .: "key"
    kid <- o .: "id"
    created <- o .: "created"
    expires <- o .: "expires"
    caps <- o .: "capabilities"
    desc <- o .:? "description"
    pure
      KeyCreateResponse
        { kcrKey = key
        , kcrMeta =
            Key
              { keyId = kid
              , keyCreated = created
              , keyExpires = expires
              , keyCapabilities = caps
              , keyDescription = desc
              }
        }

-- | Delete an auth key
deleteKey :: Client -> Text -> IO (Either TailscaleError ())
deleteKey client kid = do
  let url = buildTailnetURL client ["keys", kid]
  baseReq <- parseRequest $ T.unpack url
  let req = baseReq{method = "DELETE"}
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right _ -> pure $ Right ()

-- | Create capabilities for a reusable key
mkReusableKey :: [Text] -> KeyCapabilities
mkReusableKey tags =
  KeyCapabilities
    { kcDevices =
        Just
          KeyDeviceCapabilities
            { kdcCreate =
                KeyDeviceCreateCapabilities
                  { kdccReusable = True
                  , kdccEphemeral = False
                  , kdccPreauthorized = False
                  , kdccTags = if null tags then Nothing else Just tags
                  }
            }
    }

-- | Create capabilities for an ephemeral key
mkEphemeralKey :: [Text] -> KeyCapabilities
mkEphemeralKey tags =
  KeyCapabilities
    { kcDevices =
        Just
          KeyDeviceCapabilities
            { kdcCreate =
                KeyDeviceCreateCapabilities
                  { kdccReusable = False
                  , kdccEphemeral = True
                  , kdccPreauthorized = False
                  , kdccTags = if null tags then Nothing else Just tags
                  }
            }
    }

-- | Create capabilities for a preauthorized key
mkPreauthorizedKey :: [Text] -> KeyCapabilities
mkPreauthorizedKey tags =
  KeyCapabilities
    { kcDevices =
        Just
          KeyDeviceCapabilities
            { kdcCreate =
                KeyDeviceCreateCapabilities
                  { kdccReusable = False
                  , kdccEphemeral = False
                  , kdccPreauthorized = True
                  , kdccTags = if null tags then Nothing else Just tags
                  }
            }
    }
