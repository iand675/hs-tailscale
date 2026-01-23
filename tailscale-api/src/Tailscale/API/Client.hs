{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

{- |
Module      : Tailscale.API.Client
Description : HTTP client for the Tailscale API
License     : BSD-3-Clause

This module provides the core HTTP client functionality for interacting
with the Tailscale API.
-}
module Tailscale.API.Client (
  -- * Client Types
  Client (..),
  AuthMethod (..),
  APIKey (..),

  -- * Client Construction
  newClient,
  defaultClient,

  -- * URL Building
  buildURL,
  buildTailnetURL,
  buildQueryString,
  urlEncodeText,

  -- * Request Execution
  doRequest,
  doRequestWithBody,
  sendRequest,

  -- * Response Handling
  handleErrorResponse,
  parseJsonResponse,

  -- * Constants
  defaultBaseURL,
  maxResponseSize,
) where

import Control.Exception (SomeException, try)
import Data.Aeson (FromJSON, ToJSON, eitherDecode, encode)
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types.Header (hAccept, hContentType, hUserAgent)
import Network.HTTP.Types.Status (statusCode)
import Network.HTTP.Types.URI (urlEncode)

import Tailscale.API.Types

-- | Default base URL for the Tailscale API
defaultBaseURL :: Text
defaultBaseURL = "https://api.tailscale.com"

-- | Maximum response size (10 MB)
maxResponseSize :: Int
maxResponseSize = 10 * 1024 * 1024

-- | Authentication method for the Tailscale API
class AuthMethod a where
  applyAuth :: a -> Request -> Request

-- | API key authentication (uses HTTP Basic Auth with API key as username)
newtype APIKey = APIKey {unAPIKey :: Text}
  deriving (Eq, Show)

instance AuthMethod APIKey where
  applyAuth (APIKey key) req =
    applyBasicAuth (TE.encodeUtf8 key) "" req

-- | Tailscale API client
data Client = Client
  { clientTailnet :: !Text
  , clientAuth :: !(Request -> Request)
  , clientBaseURL :: !Text
  , clientManager :: !Manager
  , clientUserAgent :: !Text
  }

-- | Create a new Tailscale API client
newClient :: (AuthMethod a) => Text -> a -> IO Client
newClient tailnet auth = do
  manager <- newManager tlsManagerSettings
  pure
    Client
      { clientTailnet = tailnet
      , clientAuth = applyAuth auth
      , clientBaseURL = defaultBaseURL
      , clientManager = manager
      , clientUserAgent = "hs-tailscale-api/0.1.0.0"
      }

-- | Create a client with a custom manager
defaultClient :: (AuthMethod a) => Text -> a -> Manager -> Client
defaultClient tailnet auth manager =
  Client
    { clientTailnet = tailnet
    , clientAuth = applyAuth auth
    , clientBaseURL = defaultBaseURL
    , clientManager = manager
    , clientUserAgent = "hs-tailscale-api/0.1.0.0"
    }

-- | Build a URL from path elements
buildURL :: Client -> [Text] -> Text
buildURL client pathElements =
  clientBaseURL client <> "/" <> T.intercalate "/" (map urlEncodeText pathElements)

-- | Build a tailnet-specific URL
buildTailnetURL :: Client -> [Text] -> Text
buildTailnetURL client pathElements =
  buildURL client ("api" : "v2" : "tailnet" : clientTailnet client : pathElements)

-- | URL-encode a text value
urlEncodeText :: Text -> Text
urlEncodeText = TE.decodeUtf8 . urlEncode False . TE.encodeUtf8

-- | Build a query string from key-value pairs
buildQueryString :: [(Text, Text)] -> Text
buildQueryString [] = ""
buildQueryString params =
  "?" <> T.intercalate "&" (map encodeParam params)
 where
  encodeParam (k, v) = urlEncodeText k <> "=" <> urlEncodeText v

-- | Execute an HTTP request
doRequest :: Client -> Request -> IO (Either TailscaleError LBS.ByteString)
doRequest client req = do
  let req' = clientAuth client $ addHeaders req
  sendRequest client req'

-- | Execute an HTTP request with a JSON body
doRequestWithBody ::
  (ToJSON a) => Client -> Request -> a -> IO (Either TailscaleError LBS.ByteString)
doRequestWithBody client req body = do
  let req' =
        req
          { requestBody = RequestBodyLBS (encode body)
          , requestHeaders = (hContentType, "application/json") : requestHeaders req
          }
  doRequest client req'

-- | Send an HTTP request and handle the response
sendRequest :: Client -> Request -> IO (Either TailscaleError LBS.ByteString)
sendRequest client req = do
  result <- try $ httpLbs req (clientManager client)
  case result of
    Left (e :: SomeException) ->
      pure $ Left $ NetworkError $ T.pack $ show e
    Right response -> do
      let status = statusCode $ responseStatus response
          body = responseBody response
      if LBS.length body > fromIntegral maxResponseSize
        then pure $ Left $ HttpError "Response body exceeds maximum size"
        else
          if status >= 200 && status < 300
            then pure $ Right body
            else handleErrorResponse body status

-- | Handle an error response from the API
handleErrorResponse :: LBS.ByteString -> Int -> IO (Either TailscaleError a)
handleErrorResponse body status =
  case eitherDecode body of
    Right errResp -> pure $ Left $ ApiError errResp
    Left _ ->
      pure $
        Left $
          ApiError $
            ErrResponse
              { errStatus = status
              , errMessage = TE.decodeUtf8 $ LBS.toStrict body
              }

-- | Add standard headers to a request
addHeaders :: Request -> Request
addHeaders req =
  req
    { requestHeaders =
        (hAccept, "application/json")
          : (hUserAgent, "hs-tailscale-api/0.1.0.0")
          : requestHeaders req
    }

-- | Parse a JSON response into the expected type
parseJsonResponse :: (FromJSON a) => Either TailscaleError LBS.ByteString -> Either TailscaleError a
parseJsonResponse (Left err) = Left err
parseJsonResponse (Right body) =
  case eitherDecode body of
    Left e -> Left $ JsonError $ T.pack e
    Right a -> Right a
