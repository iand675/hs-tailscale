{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- |
-- Module      : Tailscale.DNS
-- Description : DNS configuration API
-- License     : BSD-3-Clause
--
-- This module provides functions for managing DNS settings in a Tailscale network.
module Tailscale.DNS
  ( -- * DNS Configuration
    getDNSConfig
  , setDNSConfig

    -- * Nameservers
  , getNameServers
  , setNameServers

    -- * DNS Preferences
  , getDNSPreferences
  , setDNSPreferences

    -- * Search Paths
  , getSearchPaths
  , setSearchPaths
  ) where

import Data.Aeson (FromJSON, eitherDecode, encode, object, (.=))
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Client (Request (..), parseRequest)
import Network.HTTP.Types.Header (hContentType)

import Tailscale.Client
import Tailscale.Types

-- | Get the full DNS configuration for the tailnet
--
-- @
-- config <- getDNSConfig client
-- @
getDNSConfig :: Client -> IO (Either TailscaleError DNSConfig)
getDNSConfig client = do
  let url = buildTailnetURL client ["dns", "config"]
  req <- parseRequest $ T.unpack url
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Set the DNS configuration for the tailnet
--
-- @
-- result <- setDNSConfig client config
-- @
setDNSConfig :: Client -> DNSConfig -> IO (Either TailscaleError DNSConfig)
setDNSConfig client config = do
  let url = buildTailnetURL client ["dns", "config"]
  baseReq <- parseRequest $ T.unpack url
  let req = baseReq
        { method = "POST"
        , requestBody = RequestBodyLBS $ encode config
        , requestHeaders = [(hContentType, "application/json")]
        }
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Get the DNS nameservers for the tailnet
--
-- @
-- nameservers <- getNameServers client
-- @
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
--
-- @
-- result <- setNameServers client ["8.8.8.8", "8.8.4.4"]
-- @
setNameServers :: Client -> [Text] -> IO (Either TailscaleError DNSNameServersPostResponse)
setNameServers client nameservers = do
  let url = buildTailnetURL client ["dns", "nameservers"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["dns" .= nameservers]
      req = baseReq
        { method = "POST"
        , requestBody = RequestBodyLBS $ encode body
        , requestHeaders = [(hContentType, "application/json")]
        }
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Get the DNS preferences for the tailnet
--
-- @
-- prefs <- getDNSPreferences client
-- @
getDNSPreferences :: Client -> IO (Either TailscaleError DNSPreferences)
getDNSPreferences client = do
  let url = buildTailnetURL client ["dns", "preferences"]
  req <- parseRequest $ T.unpack url
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Set the DNS preferences for the tailnet
--
-- @
-- result <- setDNSPreferences client True  -- Enable MagicDNS
-- @
setDNSPreferences :: Client -> Bool -> IO (Either TailscaleError DNSPreferences)
setDNSPreferences client magicDNS = do
  let url = buildTailnetURL client ["dns", "preferences"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["magicDNS" .= magicDNS]
      req = baseReq
        { method = "POST"
        , requestBody = RequestBodyLBS $ encode body
        , requestHeaders = [(hContentType, "application/json")]
        }
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Get the DNS search paths for the tailnet
--
-- @
-- paths <- getSearchPaths client
-- @
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
--
-- @
-- result <- setSearchPaths client ["example.com", "corp.example.com"]
-- @
setSearchPaths :: Client -> [Text] -> IO (Either TailscaleError [Text])
setSearchPaths client searchPaths = do
  let url = buildTailnetURL client ["dns", "searchpaths"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["searchPaths" .= searchPaths]
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
      Right (DNSSearchPaths paths) -> pure $ Right paths

-- | Parse a JSON response into the expected type
parseJsonResponse :: FromJSON a => Either TailscaleError LBS.ByteString -> Either TailscaleError a
parseJsonResponse (Left err) = Left err
parseJsonResponse (Right body) =
  case eitherDecode body of
    Left e -> Left $ JsonError $ T.pack e
    Right a -> Right a
