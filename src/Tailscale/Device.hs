{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Tailscale.Device
Description : Device management API
License     : BSD-3-Clause

This module provides functions for managing devices in a Tailscale network.
-}
module Tailscale.Device (
  -- * Listing Devices
  getDevices,
  getDevice,

  -- * Device Management
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

import Tailscale.Client
import Tailscale.Types

{- | Get all devices in the tailnet

@
devices <- getDevices client Nothing
-- or with field options
devices <- getDevices client (Just deviceAllFields)
@
-}
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

-- | Parse the devices response
parseDevicesResponse :: LBS.ByteString -> Either TailscaleError [Device]
parseDevicesResponse body =
  case eitherDecode body of
    Left e -> Left $ JsonError $ T.pack e
    Right (DevicesWrapper devices) -> Right devices

-- | Wrapper for the devices list response
newtype DevicesWrapper = DevicesWrapper {_dwDevices :: [Device]}

instance FromJSON DevicesWrapper where
  parseJSON = withObject "DevicesWrapper" $ \o ->
    DevicesWrapper <$> o .: "devices"

{- | Get a specific device by ID

@
device <- getDevice client "device-id-123" Nothing
@
-}
getDevice :: Client -> Text -> Maybe DeviceFieldsOpts -> IO (Either TailscaleError Device)
getDevice client devId mFields = do
  let url = buildURL client ["api", "v2", "device", devId]
      urlWithFields = case mFields of
        Nothing -> url
        Just (DeviceFieldsOpts f) -> url <> buildQueryString [("fields", f)]
  req <- parseRequest $ T.unpack urlWithFields
  result <- doRequest client req
  pure $ parseJsonResponse result

{- | Delete a device from the tailnet

@
result <- deleteDevice client "device-id-123"
@
-}
deleteDevice :: Client -> Text -> IO (Either TailscaleError ())
deleteDevice client devId = do
  let url = buildURL client ["api", "v2", "device", devId]
  baseReq <- parseRequest $ T.unpack url
  let req = baseReq{method = "DELETE"}
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right _ -> pure $ Right ()

{- | Authorize a device (shorthand for setAuthorized with True)

@
result <- authorizeDevice client "device-id-123"
@
-}
authorizeDevice :: Client -> Text -> IO (Either TailscaleError ())
authorizeDevice client devId = setAuthorized client devId True

{- | Set the authorization status of a device

@
result <- setAuthorized client "device-id-123" True
@
-}
setAuthorized :: Client -> Text -> Bool -> IO (Either TailscaleError ())
setAuthorized client devId authorized = do
  let url = buildURL client ["api", "v2", "device", devId, "authorized"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["authorized" .= authorized]
      req =
        baseReq
          { method = "POST"
          , requestBody = requestBodyLBS $ encode body
          , requestHeaders = [(hContentType, "application/json")]
          }
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right _ -> pure $ Right ()

{- | Set ACL tags on a device

@
result <- setTags client "device-id-123" ["tag:server", "tag:prod"]
@
-}
setTags :: Client -> Text -> [Text] -> IO (Either TailscaleError ())
setTags client devId tags = do
  let url = buildURL client ["api", "v2", "device", devId, "tags"]
  baseReq <- parseRequest $ T.unpack url
  let body = object ["tags" .= tags]
      req =
        baseReq
          { method = "POST"
          , requestBody = requestBodyLBS $ encode body
          , requestHeaders = [(hContentType, "application/json")]
          }
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right _ -> pure $ Right ()

-- | Parse a JSON response into the expected type
parseJsonResponse :: (FromJSON a) => Either TailscaleError LBS.ByteString -> Either TailscaleError a
parseJsonResponse (Left err) = Left err
parseJsonResponse (Right body) =
  case eitherDecode body of
    Left e -> Left $ JsonError $ T.pack e
    Right a -> Right a

-- | Create a request body from lazy bytestring
requestBodyLBS :: LBS.ByteString -> RequestBody
requestBodyLBS = RequestBodyLBS
