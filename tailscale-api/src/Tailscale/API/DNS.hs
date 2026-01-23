{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Tailscale.API.DNS
Description : DNS configuration API
License     : BSD-3-Clause
-}
module Tailscale.API.DNS (
  getDNSConfig,
  setDNSConfig,
  getNameServers,
  setNameServers,
  getDNSPreferences,
  setDNSPreferences,
  getSearchPaths,
  setSearchPaths,
) where

import Data.Aeson (eitherDecode, encode, object, (.=))
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Client (Request (..), RequestBody (RequestBodyLBS), parseRequest)
import Network.HTTP.Types.Header (hContentType)

import Tailscale.API.Client
import Tailscale.API.Types

-- | Get the full DNS configuration for the tailnet
getDNSConfig :: Client -> IO (Either TailscaleError DNSConfig)
getDNSConfig client = do
  let url = buildTailnetURL client ["dns", "config"]
  req <- parseRequest $ T.unpack url
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Set the DNS configuration for the tailnet
setDNSConfig :: Client -> DNSConfig -> IO (Either TailscaleError DNSConfig)
setDNSConfig client config = do
  let url = buildTailnetURL client ["dns", "config"]
  baseReq <- parseRequest $ T.unpack url
  let req =
        baseReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ encode config
          , requestHeaders = [(hContentType, "application/json")]
          }
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Get the DNS nameservers for the tailnet
getNameServers :: Client -> IO (Either TailscaleError [Text])
getNameServers client = do
  let url = buildTailnetURL client ["dns", "nameservers"]
  req <- parseRequest $ T.unpack url
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right body -> case eitherDecode body of
      Left e -> pure $ Left $ JsonError $ T.pack e
      Right (DNSNameServers ns) -> pure $ Right ns

-- | Set the DNS nameservers for the tailnet
setNameServers :: Client -> [Text] -> IO (Either TailscaleError DNSNameServersPostResponse)
setNameServers client nameservers = do
  let url = buildTailnetURL client ["dns", "nameservers"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["dns" .= nameservers]
      req =
        baseReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ encode body
          , requestHeaders = [(hContentType, "application/json")]
          }
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Get the DNS preferences for the tailnet
getDNSPreferences :: Client -> IO (Either TailscaleError DNSPreferences)
getDNSPreferences client = do
  let url = buildTailnetURL client ["dns", "preferences"]
  req <- parseRequest $ T.unpack url
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Set the DNS preferences for the tailnet
setDNSPreferences :: Client -> Bool -> IO (Either TailscaleError DNSPreferences)
setDNSPreferences client magicDNS = do
  let url = buildTailnetURL client ["dns", "preferences"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["magicDNS" .= magicDNS]
      req =
        baseReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ encode body
          , requestHeaders = [(hContentType, "application/json")]
          }
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Get the DNS search paths for the tailnet
getSearchPaths :: Client -> IO (Either TailscaleError [Text])
getSearchPaths client = do
  let url = buildTailnetURL client ["dns", "searchpaths"]
  req <- parseRequest $ T.unpack url
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right body -> case eitherDecode body of
      Left e -> pure $ Left $ JsonError $ T.pack e
      Right (DNSSearchPaths paths) -> pure $ Right paths

-- | Set the DNS search paths for the tailnet
setSearchPaths :: Client -> [Text] -> IO (Either TailscaleError [Text])
setSearchPaths client searchPaths = do
  let url = buildTailnetURL client ["dns", "searchpaths"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["searchPaths" .= searchPaths]
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
      Right (DNSSearchPaths paths) -> pure $ Right paths
