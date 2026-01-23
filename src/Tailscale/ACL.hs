{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Tailscale.ACL
Description : Access Control List (ACL) management API
License     : BSD-3-Clause

This module provides functions for managing ACLs in a Tailscale network.
-}
module Tailscale.ACL (
  -- * Getting ACLs
  getACL,
  getACLHuJSON,

  -- * Setting ACLs
  setACL,
  setACLHuJSON,

  -- * ACL Preview
  previewACLForUser,
  previewACLForIPPort,
  previewACLHuJSONForUser,
  previewACLHuJSONForIPPort,

  -- * ACL Validation
  validateACLJSON,
) where

import Data.Aeson (FromJSON, eitherDecode, encode, object, (.=))
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Network.HTTP.Client (
  Request (..),
  RequestBody (RequestBodyLBS),
  parseRequest,
  requestHeaders,
 )
import Network.HTTP.Types.Header (hAccept, hContentType, hIfMatch)

import Tailscale.Client
import Tailscale.Types

{- | Get the ACL for the tailnet as parsed JSON

@
acl <- getACL client
@
-}
getACL :: Client -> IO (Either TailscaleError ACL)
getACL client = do
  let url = buildTailnetURL client ["acl"]
  req <- parseRequest $ T.unpack url
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right body -> case eitherDecode body of
      Left e -> pure $ Left $ JsonError $ T.pack e
      Right parsedData ->
        pure $
          Right
            ACL
              { aclData = parsedData
              , aclETag = Nothing -- ETag would need to be extracted from response headers
              }

{- | Get the ACL for the tailnet as HuJSON (human-friendly JSON with comments)

@
acl <- getACLHuJSON client
@
-}
getACLHuJSON :: Client -> IO (Either TailscaleError ACLHuJSON)
getACLHuJSON client = do
  let url = buildTailnetURL client ["acl"]
  baseReq <- parseRequest $ T.unpack url
  let req =
        baseReq
          { requestHeaders = (hAccept, "application/hujson") : requestHeaders baseReq
          }
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right body ->
      pure $
        Right
          ACLHuJSON
            { aclhRaw = TE.decodeUtf8 $ LBS.toStrict body
            , aclhWarnings = Nothing
            , aclhETag = Nothing
            }

{- | Set the ACL for the tailnet

@
result <- setACL client acl True  -- True to avoid collisions using ETag
@
-}
setACL :: Client -> ACL -> Bool -> IO (Either TailscaleError ACL)
setACL client acl avoidCollisions = do
  let url = buildTailnetURL client ["acl"]
  baseReq <- parseRequest $ T.unpack url
  let headers =
        (hContentType, "application/json")
          : if avoidCollisions
            then case aclETag acl of
              Just etag -> [(hIfMatch, TE.encodeUtf8 etag)]
              Nothing -> []
            else []
      req =
        baseReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ encode (aclData acl)
          , requestHeaders = headers
          }
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right body -> case eitherDecode body of
      Left e -> pure $ Left $ JsonError $ T.pack e
      Right parsedData' ->
        pure $
          Right
            ACL
              { aclData = parsedData'
              , aclETag = Nothing
              }

{- | Set the ACL for the tailnet using HuJSON format

@
result <- setACLHuJSON client aclHuJSON True
@
-}
setACLHuJSON :: Client -> ACLHuJSON -> Bool -> IO (Either TailscaleError ACLHuJSON)
setACLHuJSON client acl avoidCollisions = do
  let url = buildTailnetURL client ["acl"]
  baseReq <- parseRequest $ T.unpack url
  let headers =
        [(hContentType, "application/hujson"), (hAccept, "application/hujson")]
          ++ if avoidCollisions
            then case aclhETag acl of
              Just etag -> [(hIfMatch, TE.encodeUtf8 etag)]
              Nothing -> []
            else []
      req =
        baseReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ LBS.fromStrict $ TE.encodeUtf8 $ aclhRaw acl
          , requestHeaders = headers
          }
  result <- doRequest client req
  case result of
    Left err -> pure $ Left err
    Right body ->
      pure $
        Right
          ACLHuJSON
            { aclhRaw = TE.decodeUtf8 $ LBS.toStrict body
            , aclhWarnings = Nothing
            , aclhETag = Nothing
            }

{- | Preview ACL rules that apply to a specific user

@
preview <- previewACLForUser client acl "user@example.com"
@
-}
previewACLForUser :: Client -> ACL -> Text -> IO (Either TailscaleError ACLPreview)
previewACLForUser client acl user = do
  let url = buildTailnetURL client ["acl", "preview"]
      urlWithParams = url <> buildQueryString [("previewFor", "user"), ("user", user)]
  baseReq <- parseRequest $ T.unpack urlWithParams
  let req =
        baseReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ encode (aclData acl)
          , requestHeaders = [(hContentType, "application/json")]
          }
  result <- doRequest client req
  pure $ parseJsonResponse result

{- | Preview ACL rules that apply to a specific IP:port

@
preview <- previewACLForIPPort client acl "192.168.1.1:443"
@
-}
previewACLForIPPort :: Client -> ACL -> Text -> IO (Either TailscaleError ACLPreview)
previewACLForIPPort client acl ipport = do
  let url = buildTailnetURL client ["acl", "preview"]
      urlWithParams = url <> buildQueryString [("previewFor", "ipport"), ("ipport", ipport)]
  baseReq <- parseRequest $ T.unpack urlWithParams
  let req =
        baseReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ encode (aclData acl)
          , requestHeaders = [(hContentType, "application/json")]
          }
  result <- doRequest client req
  pure $ parseJsonResponse result

{- | Preview ACL rules for a user using HuJSON format

@
preview <- previewACLHuJSONForUser client aclHuJSON "user@example.com"
@
-}
previewACLHuJSONForUser :: Client -> ACLHuJSON -> Text -> IO (Either TailscaleError ACLPreview)
previewACLHuJSONForUser client acl user = do
  let url = buildTailnetURL client ["acl", "preview"]
      urlWithParams = url <> buildQueryString [("previewFor", "user"), ("user", user)]
  baseReq <- parseRequest $ T.unpack urlWithParams
  let req =
        baseReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ LBS.fromStrict $ TE.encodeUtf8 $ aclhRaw acl
          , requestHeaders = [(hContentType, "application/hujson")]
          }
  result <- doRequest client req
  pure $ parseJsonResponse result

{- | Preview ACL rules for an IP:port using HuJSON format

@
preview <- previewACLHuJSONForIPPort client aclHuJSON "192.168.1.1:443"
@
-}
previewACLHuJSONForIPPort :: Client -> ACLHuJSON -> Text -> IO (Either TailscaleError ACLPreview)
previewACLHuJSONForIPPort client acl ipport = do
  let url = buildTailnetURL client ["acl", "preview"]
      urlWithParams = url <> buildQueryString [("previewFor", "ipport"), ("ipport", ipport)]
  baseReq <- parseRequest $ T.unpack urlWithParams
  let req =
        baseReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ LBS.fromStrict $ TE.encodeUtf8 $ aclhRaw acl
          , requestHeaders = [(hContentType, "application/hujson")]
          }
  result <- doRequest client req
  pure $ parseJsonResponse result

{- | Validate an ACL by testing connectivity between source and destination

@
result <- validateACLJSON client "user@example.com" "server:22"
@
-}
validateACLJSON :: Client -> Text -> Text -> IO (Either TailscaleError (Maybe ACLTestError))
validateACLJSON client source dest = do
  let url = buildTailnetURL client ["acl", "validate"]
  baseReq <- parseRequest $ T.unpack url
  let reqBody =
        object
          [ "src" .= source
          , "dst" .= dest
          ]
      req =
        baseReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ encode reqBody
          , requestHeaders = [(hContentType, "application/json")]
          }
  result <- doRequest client req
  case result of
    Left (ApiError err) ->
      -- Try to parse as ACLTestError
      pure $
        Right $
          Just
            ACLTestError
              { ateResponse = err
              , ateData = []
              }
    Left err -> pure $ Left err
    Right respBody -> case eitherDecode respBody of
      Left _ -> pure $ Right Nothing -- Success, no errors
      Right testErr -> pure $ Right $ Just testErr

-- | Parse a JSON response into the expected type
parseJsonResponse :: (FromJSON a) => Either TailscaleError LBS.ByteString -> Either TailscaleError a
parseJsonResponse (Left err) = Left err
parseJsonResponse (Right body) =
  case eitherDecode body of
    Left e -> Left $ JsonError $ T.pack e
    Right a -> Right a
