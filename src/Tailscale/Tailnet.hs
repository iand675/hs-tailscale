{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Tailscale.Tailnet
Description : Tailnet management API
License     : BSD-3-Clause

This module provides functions for managing tailnet-level settings.
-}
module Tailscale.Tailnet (
  -- * Tailnet Management
  deleteTailnet,
) where

import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Client (Request (..), parseRequest)

import Tailscale.Client
import Tailscale.Types

{- | Delete a tailnet

WARNING: This is a destructive operation that cannot be undone.
Use with extreme caution.

@
result <- deleteTailnet client "tailnet-id"
@
-}
deleteTailnet :: Client -> Text -> IO (Either TailscaleError ())
deleteTailnet client tailnetId = do
  let url = buildURL client ["api", "v2", "tailnet", tailnetId]
  baseReq <- parseRequest $ T.unpack url
  let req = baseReq{method = "DELETE"}
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right _ -> pure $ Right ()
