{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- |
-- Module      : Tailscale.Routes
-- Description : Subnet routes management API
-- License     : BSD-3-Clause
--
-- This module provides functions for managing subnet routes on devices
-- in a Tailscale network.
module Tailscale.Routes
  ( -- * Route Management
    getRoutes
  , setRoutes
  ) where

import Data.Aeson (FromJSON, eitherDecode, encode, object, (.=))
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Client (Request (..), parseRequest)
import Network.HTTP.Types.Header (hContentType)

import Tailscale.Client
import Tailscale.Types

-- | Get the routes for a device
--
-- @
-- routes <- getRoutes client "device-id-123"
-- @
getRoutes :: Client -> Text -> IO (Either TailscaleError Routes)
getRoutes client deviceId = do
  let url = buildURL client ["api", "v2", "device", deviceId, "routes"]
  req <- parseRequest $ T.unpack url
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Set the enabled routes for a device
--
-- This enables the specified subnet routes on the device. The routes
-- must first be advertised by the device.
--
-- @
-- result <- setRoutes client "device-id-123" ["10.0.0.0/8", "192.168.1.0/24"]
-- @
setRoutes :: Client -> Text -> [Text] -> IO (Either TailscaleError Routes)
setRoutes client deviceId routes = do
  let url = buildURL client ["api", "v2", "device", deviceId, "routes"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["routes" .= routes]
      req = baseReq
        { method = "POST"
        , requestBody = RequestBodyLBS $ encode body
        , requestHeaders = [(hContentType, "application/json")]
        }
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Parse a JSON response into the expected type
parseJsonResponse :: FromJSON a => Either TailscaleError LBS.ByteString -> Either TailscaleError a
parseJsonResponse (Left err) = Left err
parseJsonResponse (Right body) =
  case eitherDecode body of
    Left e -> Left $ JsonError $ T.pack e
    Right a -> Right a
