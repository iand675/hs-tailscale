{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Tailscale.API.Device
Description : Device management API
License     : BSD-3-Clause
-}
module Tailscale.API.Device (
  getDevices,
  getDevice,
  deleteDevice,
  authorizeDevice,
  setAuthorized,
  setTags,
) where

import Data.Aeson (FromJSON (..), eitherDecode, encode, object, withObject, (.:), (.=))
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Client (Request (..), RequestBody (RequestBodyLBS), parseRequest)
import Network.HTTP.Types.Header (hContentType)

import Tailscale.API.Client
import Tailscale.API.Types

-- | Get all devices in the tailnet
getDevices :: Client -> Maybe DeviceFieldsOpts -> IO (Either TailscaleError [Device])
getDevices client mFields = do
  let url = buildTailnetURL client ["devices"]
      urlWithFields = case mFields of
        Nothing -> url
        Just (DeviceFieldsOpts f) -> url <> buildQueryString [("fields", f)]
  req <- parseRequest $ T.unpack urlWithFields
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right body -> pure $ parseDevicesResponse body

parseDevicesResponse :: LBS.ByteString -> Either TailscaleError [Device]
parseDevicesResponse body =
  case eitherDecode body of
    Left e -> Left $ JsonError $ T.pack e
    Right (DevicesWrapper devices) -> Right devices

newtype DevicesWrapper = DevicesWrapper {_dwDevices :: [Device]}

instance FromJSON DevicesWrapper where
  parseJSON = withObject "DevicesWrapper" $ \o ->
    DevicesWrapper <$> o .: "devices"

-- | Get a specific device by ID
getDevice :: Client -> Text -> Maybe DeviceFieldsOpts -> IO (Either TailscaleError Device)
getDevice client devId mFields = do
  let url = buildURL client ["api", "v2", "device", devId]
      urlWithFields = case mFields of
        Nothing -> url
        Just (DeviceFieldsOpts f) -> url <> buildQueryString [("fields", f)]
  req <- parseRequest $ T.unpack urlWithFields
  result <- doRequest client req
  pure $ parseJsonResponse result

-- | Delete a device from the tailnet
deleteDevice :: Client -> Text -> IO (Either TailscaleError ())
deleteDevice client devId = do
  let url = buildURL client ["api", "v2", "device", devId]
  baseReq <- parseRequest $ T.unpack url
  let req = baseReq{method = "DELETE"}
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right _ -> pure $ Right ()

-- | Authorize a device
authorizeDevice :: Client -> Text -> IO (Either TailscaleError ())
authorizeDevice client devId = setAuthorized client devId True

-- | Set the authorization status of a device
setAuthorized :: Client -> Text -> Bool -> IO (Either TailscaleError ())
setAuthorized client devId authorized = do
  let url = buildURL client ["api", "v2", "device", devId, "authorized"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["authorized" .= authorized]
      req =
        baseReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ encode body
          , requestHeaders = [(hContentType, "application/json")]
          }
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right _ -> pure $ Right ()

-- | Set ACL tags on a device
setTags :: Client -> Text -> [Text] -> IO (Either TailscaleError ())
setTags client devId tags = do
  let url = buildURL client ["api", "v2", "device", devId, "tags"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["tags" .= tags]
      req =
        baseReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ encode body
          , requestHeaders = [(hContentType, "application/json")]
          }
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right _ -> pure $ Right ()
