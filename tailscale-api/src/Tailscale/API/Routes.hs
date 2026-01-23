{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Tailscale.API.Routes
Description : Subnet routes management API
License     : BSD-3-Clause
-}
module Tailscale.API.Routes (
  getRoutes,
  setRoutes,
) where

import Data.Aeson (encode, object, (.=))
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Client (Request (..), RequestBody (RequestBodyLBS), parseRequest)
import Network.HTTP.Types.Header (hContentType)

import Tailscale.API.Client
import Tailscale.API.Types

-- | Get the routes for a device
getRoutes :: Client -> Text -> IO (Either TailscaleError Routes)
getRoutes client devId = do
  let url = buildURL client ["api", "v2", "device", devId, "routes"]
  req <- parseRequest $ T.unpack url
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Set the enabled routes for a device
setRoutes :: Client -> Text -> [Text] -> IO (Either TailscaleError Routes)
setRoutes client devId routes = do
  let url = buildURL client ["api", "v2", "device", devId, "routes"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["routes" .= routes]
      req =
        baseReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ encode body
          , requestHeaders = [(hContentType, "application/json")]
          }
  result <- doRequest client req
  pure $ parseJsonResponse result
