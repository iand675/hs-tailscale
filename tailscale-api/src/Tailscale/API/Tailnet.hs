{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Tailscale.API.Tailnet
Description : Tailnet management API
License     : BSD-3-Clause
-}
module Tailscale.API.Tailnet (
  deleteTailnet,
) where

import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Client (Request (..), parseRequest)

import Tailscale.API.Client
import Tailscale.API.Types

-- | Delete a tailnet (use with extreme caution)
deleteTailnet :: Client -> Text -> IO (Either TailscaleError ())
deleteTailnet client tailnetId = do
  let url = buildURL client ["api", "v2", "tailnet", tailnetId]
  baseReq <- parseRequest $ T.unpack url
  let req = baseReq{method = "DELETE"}
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right _ -> pure $ Right ()
