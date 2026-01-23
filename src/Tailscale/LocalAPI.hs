{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : Tailscale.LocalAPI
-- Description : Client for the Tailscale LocalAPI (tailscaled daemon)
-- License     : BSD-3-Clause
--
-- This module provides a client for communicating with the local tailscaled
-- daemon via its LocalAPI. This allows you to:
--
-- * Get the current Tailscale status and IPs
-- * Obtain TLS certificates for HTTPS
-- * Identify who is connecting to your service (WhoIs)
-- * Make outbound connections through Tailscale
-- * Monitor for status changes
--
-- = Prerequisites
--
-- The tailscaled daemon must be running on the local machine. On Linux, it
-- communicates via a Unix socket at @\/var\/run\/tailscale\/tailscaled.sock@.
-- On macOS, it uses a different socket path.
--
-- = Example Usage
--
-- @
-- import Tailscale.LocalAPI
--
-- main :: IO ()
-- main = do
--   client <- newLocalClient
--
--   -- Get current status
--   status <- getStatus client
--   case status of
--     Left err -> print err
--     Right s -> do
--       print $ statusBackendState s
--       print $ statusTailscaleIPs s
--
--   -- Get TLS certificate for your domain
--   cert <- getCertPair client "myhost.tail-scale.ts.net"
--   case cert of
--     Left err -> print err
--     Right (CertPair certPEM keyPEM) -> do
--       -- Use with Warp TLS or other server
--       putStrLn "Got certificate!"
-- @
module Tailscale.LocalAPI
  ( -- * Client
    LocalClient (..)
  , newLocalClient
  , newLocalClientWithSocket

    -- * Status
  , getStatus
  , getStatusWithoutPeers

    -- * Identity
  , whoIs
  , whoIsNodeKey

    -- * Certificates
  , getCertPair
  , expandSNIName

    -- * Preferences
  , getPrefs

    -- * Ping
  , ping

    -- * Serve Configuration
  , getServeConfig
  , setServeConfig

    -- * Network Lock
  , getNetworkLockStatus

    -- * File Transfer
  , getWaitingFiles
  , getFileTargets

    -- * Utilities
  , getTailscaleIPs
  , getCertDomains
  , isRunning

    -- * Re-exports
  , module Tailscale.LocalAPI.Types
  ) where

import Control.Exception (IOException, try)
import Data.Aeson (FromJSON, eitherDecode, encode)
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Network.HTTP.Client
import Network.HTTP.Client.Internal (Connection, makeConnection, openSocketConnection)
import Network.HTTP.Types.Header (hAccept, hContentType)
import Network.HTTP.Types.Status (statusCode)
import Network.Socket (Family(AF_UNIX), SocketType(Stream), SockAddr(SockAddrUnix), HostAddress, socket, connect, close)
import qualified Network.Socket.ByteString as SBS
import System.Info (os)

import Tailscale.LocalAPI.Types

-- | Default socket path for tailscaled
defaultSocketPath :: FilePath
defaultSocketPath = case os of
  "darwin" -> "/var/run/tailscaled.socket"
  _        -> "/var/run/tailscale/tailscaled.sock"

-- | Client for the Tailscale LocalAPI
data LocalClient = LocalClient
  { localClientSocketPath :: !FilePath
  , localClientManager    :: !Manager
  }

-- | Create a new LocalAPI client using the default socket path
newLocalClient :: IO LocalClient
newLocalClient = newLocalClientWithSocket defaultSocketPath

-- | Create a new LocalAPI client with a custom socket path
newLocalClientWithSocket :: FilePath -> IO LocalClient
newLocalClientWithSocket socketPath = do
  manager <- newManager $ defaultManagerSettings
    { managerRawConnection = return $ openUnixSocket socketPath
    }
  pure LocalClient
    { localClientSocketPath = socketPath
    , localClientManager = manager
    }

-- | Open a Unix socket connection
openUnixSocket :: FilePath -> Maybe HostAddress -> String -> Int -> IO Connection
openUnixSocket socketPath _ _ _ = do
  sock <- socket AF_UNIX Stream 0
  connect sock (SockAddrUnix socketPath)
  makeConnection
    (SBS.recv sock 4096)
    (SBS.sendAll sock)
    (close sock)

-- | Make a request to the LocalAPI
localRequest
  :: FromJSON a
  => LocalClient
  -> Text           -- ^ Method (GET, POST, etc.)
  -> Text           -- ^ Path
  -> Maybe LBS.ByteString  -- ^ Optional body
  -> IO (Either LocalAPIError a)
localRequest client method path mBody = do
  result <- try $ do
    initReq <- parseRequest $ "http://local-tailscaled.sock" <> T.unpack path
    let req = initReq
          { method = TE.encodeUtf8 method
          , requestHeaders =
              (hAccept, "application/json") :
              maybe [] (const [(hContentType, "application/json")]) mBody ++
              requestHeaders initReq
          , requestBody = maybe (requestBody initReq) RequestBodyLBS mBody
          , host = "local-tailscaled.sock"
          }
    httpLbs req (localClientManager client)
  case result of
    Left (e :: IOException) ->
      pure $ Left $ LocalAPIConnectionError $ T.pack $ show e
    Right response -> do
      let status = statusCode $ responseStatus response
          body = responseBody response
      if status >= 200 && status < 300
        then case eitherDecode body of
          Left e -> pure $ Left $ LocalAPIJsonError $ T.pack e
          Right a -> pure $ Right a
        else if status == 403
          then pure $ Left $ LocalAPIAccessDenied $ TE.decodeUtf8 $ LBS.toStrict body
          else if status == 412
            then pure $ Left $ LocalAPIPreconditionsFailed $ TE.decodeUtf8 $ LBS.toStrict body
            else pure $ Left $ LocalAPIHttpError status $ TE.decodeUtf8 $ LBS.toStrict body

-- | Make a request that returns raw bytes (for certificates)
localRequestRaw
  :: LocalClient
  -> Text           -- ^ Method
  -> Text           -- ^ Path
  -> Maybe LBS.ByteString
  -> IO (Either LocalAPIError LBS.ByteString)
localRequestRaw client method path mBody = do
  result <- try $ do
    initReq <- parseRequest $ "http://local-tailscaled.sock" <> T.unpack path
    let req = initReq
          { method = TE.encodeUtf8 method
          , requestBody = maybe (requestBody initReq) RequestBodyLBS mBody
          , host = "local-tailscaled.sock"
          }
    httpLbs req (localClientManager client)
  case result of
    Left (e :: IOException) ->
      pure $ Left $ LocalAPIConnectionError $ T.pack $ show e
    Right response -> do
      let status = statusCode $ responseStatus response
          body = responseBody response
      if status >= 200 && status < 300
        then pure $ Right body
        else pure $ Left $ LocalAPIHttpError status $ TE.decodeUtf8 $ LBS.toStrict body

--------------------------------------------------------------------------------
-- Status
--------------------------------------------------------------------------------

-- | Get the full status of the Tailscale daemon including peers
getStatus :: LocalClient -> IO (Either LocalAPIError Status)
getStatus client = localRequest client "GET" "/localapi/v0/status" Nothing

-- | Get the status without peer information (faster)
getStatusWithoutPeers :: LocalClient -> IO (Either LocalAPIError Status)
getStatusWithoutPeers client =
  localRequest client "GET" "/localapi/v0/status?peers=false" Nothing

-- | Check if Tailscale is running
isRunning :: LocalClient -> IO Bool
isRunning client = do
  result <- getStatusWithoutPeers client
  case result of
    Left _ -> pure False
    Right status -> pure $ statusBackendState status == StateRunning

-- | Get the Tailscale IPs for this machine
getTailscaleIPs :: LocalClient -> IO (Either LocalAPIError [TailscaleIP])
getTailscaleIPs client = do
  result <- getStatusWithoutPeers client
  case result of
    Left err -> pure $ Left err
    Right status -> pure $ Right $ maybe [] id (statusTailscaleIPs status)

-- | Get the certificate domains for this machine
getCertDomains :: LocalClient -> IO (Either LocalAPIError [Text])
getCertDomains client = do
  result <- getStatusWithoutPeers client
  case result of
    Left err -> pure $ Left err
    Right status -> pure $ Right $ maybe [] id (statusCertDomains status)

--------------------------------------------------------------------------------
-- Identity (WhoIs)
--------------------------------------------------------------------------------

-- | Identify who owns a remote address
--
-- This is useful for identifying who is connecting to your service.
-- Pass the remote address as "IP:port" or just "IP".
--
-- @
-- -- In a Warp application
-- app req respond = do
--   let remoteAddr = show (remoteHost req)
--   whoIsResult <- whoIs client remoteAddr
--   case whoIsResult of
--     Right whois -> do
--       putStrLn $ "Connection from: " <> userProfileDisplayName (whoIsUserProfile whois)
--     Left _ -> putStrLn "Unknown connection"
--   respond $ responseLBS status200 [] "Hello"
-- @
whoIs :: LocalClient -> Text -> IO (Either LocalAPIError WhoIsResponse)
whoIs client remoteAddr =
  localRequest client "GET" ("/localapi/v0/whois?addr=" <> remoteAddr) Nothing

-- | Identify a peer by their WireGuard public key
whoIsNodeKey :: LocalClient -> Text -> IO (Either LocalAPIError WhoIsResponse)
whoIsNodeKey client nodeKey =
  localRequest client "GET" ("/localapi/v0/whois?key=" <> nodeKey) Nothing

--------------------------------------------------------------------------------
-- Certificates
--------------------------------------------------------------------------------

-- | Get a TLS certificate pair for a domain
--
-- Tailscale provides automatic HTTPS certificates for your machines.
-- The domain should be your machine's MagicDNS name (e.g., "myhost.tail-scale.ts.net").
--
-- @
-- cert <- getCertPair client "myhost.tail-scale.ts.net"
-- case cert of
--   Right (CertPair certPEM keyPEM) -> do
--     -- Write to files for use with TLS
--     writeFile "cert.pem" (T.unpack certPEM)
--     writeFile "key.pem" (T.unpack keyPEM)
--   Left err -> print err
-- @
getCertPair :: LocalClient -> Text -> IO (Either LocalAPIError CertPair)
getCertPair client domain = do
  certResult <- localRequestRaw client "GET" ("/localapi/v0/cert/" <> domain <> "?type=cert") Nothing
  keyResult <- localRequestRaw client "GET" ("/localapi/v0/cert/" <> domain <> "?type=key") Nothing
  case (certResult, keyResult) of
    (Right certBody, Right keyBody) -> pure $ Right CertPair
      { certPEM = TE.decodeUtf8 $ LBS.toStrict certBody
      , keyPEM = TE.decodeUtf8 $ LBS.toStrict keyBody
      }
    (Left err, _) -> pure $ Left err
    (_, Left err) -> pure $ Left err

-- | Expand a short name to the full MagicDNS FQDN
expandSNIName :: LocalClient -> Text -> IO (Either LocalAPIError Text)
expandSNIName client name = do
  result <- getStatusWithoutPeers client
  case result of
    Left err -> pure $ Left err
    Right status -> do
      let suffix = maybe "" id (statusMagicDNSSuffix status)
      if T.null suffix
        then pure $ Right name
        else pure $ Right $ name <> "." <> suffix

--------------------------------------------------------------------------------
-- Preferences
--------------------------------------------------------------------------------

-- | Get the current preferences
getPrefs :: LocalClient -> IO (Either LocalAPIError Prefs)
getPrefs client = localRequest client "GET" "/localapi/v0/prefs" Nothing

--------------------------------------------------------------------------------
-- Ping
--------------------------------------------------------------------------------

-- | Ping a peer
ping :: LocalClient -> Text -> PingType -> IO (Either LocalAPIError PingResult)
ping client ip pingType = do
  let pingTypeStr = case pingType of
        PingTSMP    -> "TSMP"
        PingICMP    -> "ICMP"
        PingPeerAPI -> "PeerAPI"
  localRequest client "POST" ("/localapi/v0/ping?ip=" <> ip <> "&type=" <> pingTypeStr) Nothing

--------------------------------------------------------------------------------
-- Serve Configuration
--------------------------------------------------------------------------------

-- | Get the current serve configuration
getServeConfig :: LocalClient -> IO (Either LocalAPIError ServeConfig)
getServeConfig client = localRequest client "GET" "/localapi/v0/serve-config" Nothing

-- | Set the serve configuration
setServeConfig :: LocalClient -> ServeConfig -> IO (Either LocalAPIError ())
setServeConfig client config = do
  result <- localRequestRaw client "POST" "/localapi/v0/serve-config" (Just $ encode config)
  case result of
    Left err -> pure $ Left err
    Right _ -> pure $ Right ()

--------------------------------------------------------------------------------
-- Network Lock
--------------------------------------------------------------------------------

-- | Get the network lock (tailnet key authority) status
getNetworkLockStatus :: LocalClient -> IO (Either LocalAPIError NetworkLockStatus)
getNetworkLockStatus client = localRequest client "GET" "/localapi/v0/tka/status" Nothing

--------------------------------------------------------------------------------
-- File Transfer
--------------------------------------------------------------------------------

-- | Get files waiting to be received
getWaitingFiles :: LocalClient -> IO (Either LocalAPIError [WaitingFile])
getWaitingFiles client = localRequest client "GET" "/localapi/v0/files" Nothing

-- | Get available file transfer targets
getFileTargets :: LocalClient -> IO (Either LocalAPIError [FileTarget])
getFileTargets client = localRequest client "GET" "/localapi/v0/file-targets" Nothing
