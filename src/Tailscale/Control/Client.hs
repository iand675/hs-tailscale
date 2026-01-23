{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- Module      : Tailscale.Control.Client
-- Description : Tailscale control plane client
-- License     : BSD-3-Clause
--
-- Client for communicating with the Tailscale control plane (or Headscale).
module Tailscale.Control.Client
  ( -- * Client
    ControlClient (..)
  , ControlError (..)

    -- * Connection
  , newControlClient
  , closeControlClient

    -- * Operations
  , register
  , fetchNetworkMap
  , streamNetworkMap
  , updateEndpoints

    -- * Utilities
  , generateMachineKey
  , generateNodeKey
  ) where

import Control.Concurrent (forkIO, threadDelay, ThreadId, killThread)
import Control.Concurrent.STM
import Control.Exception (try, SomeException)
import Control.Monad (when)
import Data.Aeson (ToJSON, FromJSON, encode, eitherDecode)
import qualified Data.ByteArray as BA
import qualified Data.ByteString.Lazy as LBS
import Data.IORef
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Network.HTTP.Types.Header (hContentType)
import Network.HTTP.Types.Status (statusCode)

import Tailscale.Control.Protocol
import Tailscale.WireGuard.Crypto (generatePrivateKey, derivePublicKey, PrivateKey, PublicKey(..))

-- | Control client errors
data ControlError
  = ControlConnectionError !Text
  | ControlAuthError !Text
  | ControlProtocolError !Text
  | ControlNetworkError !Text
  deriving (Eq, Show)

-- | Control plane client
data ControlClient = ControlClient
  { ccConfig       :: !ControlConfig
  , ccManager      :: !Manager
  , ccNetworkMap   :: !(TVar (Maybe NetworkMap))
  , ccMapCallback  :: !(TVar (Maybe (NetworkMap -> IO ())))
  , ccStreamThread :: !(IORef (Maybe ThreadId))
  , ccClosed       :: !(IORef Bool)
  }

-- | Create a new control client
newControlClient :: ControlConfig -> IO ControlClient
newControlClient config = do
  manager <- newManager tlsManagerSettings
  networkMap <- newTVarIO Nothing
  mapCallback <- newTVarIO Nothing
  streamThread <- newIORef Nothing
  closed <- newIORef False
  pure ControlClient
    { ccConfig = config
    , ccManager = manager
    , ccNetworkMap = networkMap
    , ccMapCallback = mapCallback
    , ccStreamThread = streamThread
    , ccClosed = closed
    }

-- | Close the control client
closeControlClient :: ControlClient -> IO ()
closeControlClient client = do
  writeIORef (ccClosed client) True
  mThread <- readIORef (ccStreamThread client)
  case mThread of
    Nothing -> pure ()
    Just tid -> killThread tid

-- | Generate a new machine key
generateMachineKey :: IO MachineKey
generateMachineKey = do
  privKey <- generatePrivateKey
  let PublicKey pub = derivePublicKey privKey
  pure $ MachineKey $ BA.convert pub

-- | Generate a new node key
generateNodeKey :: IO (PrivateKey, NodeKey)
generateNodeKey = do
  privKey <- generatePrivateKey
  let PublicKey pub = derivePublicKey privKey
  pure (privKey, NodeKey $ BA.convert pub)

-- | Register this node with the control server
register
  :: ControlClient
  -> Maybe Text       -- ^ Auth key (for pre-authenticated registration)
  -> IO (Either ControlError RegisterResponse)
register client mAuthKey = do
  let config = ccConfig client
      url = ccControlURL config <> "/machine/register"

      authInfo = case mAuthKey of
        Nothing -> Nothing
        Just key -> Just AuthInfo
          { aiProvider = "authkey"
          , aiLoginName = Nothing
          , aiAuthKey = Just key
          }

      reqBody = RegisterRequest
        { rrVersion = 1
        , rrNodeKey = ccNodeKey config
        , rrOldNodeKey = Nothing
        , rrAuth = authInfo
        , rrExpiry = Nothing
        , rrHostinfo = Nothing
        , rrFollowup = Nothing
        }

  doRequest client url reqBody

-- | Fetch the network map once
fetchNetworkMap :: ControlClient -> IO (Either ControlError NetworkMap)
fetchNetworkMap client = do
  let config = ccConfig client
      url = ccControlURL config <> "/machine/map"

      reqBody = MapRequest
        { mrVersion = 1
        , mrCompress = ""
        , mrKeepAlive = False
        , mrNodeKey = ccNodeKey config
        , mrEndpoints = []
        , mrStream = False
        , mrHostinfo = Nothing
        }

  result <- doRequest client url reqBody
  case result of
    Left err -> pure $ Left err
    Right (resp :: MapResponse) ->
      case (mrspNode resp, mrspPeers resp, mrspDERPMap resp) of
        (Just self, Just peers, Just derpMap) -> do
          let netMap = NetworkMap
                { nmSelfNode = self
                , nmPeers = peers
                , nmDERPMap = derpMap
                , nmDNSConfig = mrspDNSConfig resp
                , nmPacketFilter = mrspPacketFilter resp
                , nmCollectServices = False
                , nmDomain = maybe "" id (mrspDomain resp)
                }
          atomically $ writeTVar (ccNetworkMap client) (Just netMap)
          pure $ Right netMap
        _ -> pure $ Left $ ControlProtocolError "Incomplete map response"

-- | Stream network map updates
streamNetworkMap
  :: ControlClient
  -> (NetworkMap -> IO ())  -- ^ Callback for map updates
  -> IO (Either ControlError ())
streamNetworkMap client callback = do
  atomically $ writeTVar (ccMapCallback client) (Just callback)

  -- Start streaming thread
  tid <- forkIO $ streamLoop client
  writeIORef (ccStreamThread client) (Just tid)
  pure $ Right ()

-- | Streaming loop for network map updates
streamLoop :: ControlClient -> IO ()
streamLoop client = do
  closed <- readIORef (ccClosed client)
  when (not closed) $ do
    -- Fetch map
    result <- fetchNetworkMap client
    case result of
      Left _ -> pure ()
      Right netMap -> do
        mCallback <- atomically $ readTVar (ccMapCallback client)
        case mCallback of
          Nothing -> pure ()
          Just cb -> cb netMap

    -- Wait and retry (simplified - real implementation uses long-polling)
    threadDelay 30000000  -- 30 seconds
    streamLoop client
  where
    threadDelay n = Control.Concurrent.threadDelay n

-- | Update our endpoints with the control server
updateEndpoints :: ControlClient -> [Text] -> IO (Either ControlError ())
updateEndpoints client endpoints = do
  let config = ccConfig client
      url = ccControlURL config <> "/machine/map"

      reqBody = MapRequest
        { mrVersion = 1
        , mrCompress = ""
        , mrKeepAlive = True
        , mrNodeKey = ccNodeKey config
        , mrEndpoints = endpoints
        , mrStream = False
        , mrHostinfo = Nothing
        }

  result <- doRequest client url reqBody
  case result of
    Left err -> pure $ Left err
    Right (_ :: MapResponse) -> pure $ Right ()

-- | Make a request to the control server
doRequest
  :: (ToJSON req, FromJSON resp)
  => ControlClient
  -> Text
  -> req
  -> IO (Either ControlError resp)
doRequest client urlText reqBody = do
  result <- try $ do
    initReq <- parseRequest $ T.unpack urlText
    let req = initReq
          { method = "POST"
          , requestBody = RequestBodyLBS $ encode reqBody
          , requestHeaders =
              (hContentType, "application/json") :
              requestHeaders initReq
          }
    response <- httpLbs req (ccManager client)
    pure response

  case result of
    Left (e :: SomeException) ->
      pure $ Left $ ControlNetworkError $ T.pack $ show e
    Right response -> do
      let status = statusCode $ responseStatus response
          body = responseBody response
      if status >= 200 && status < 300
        then case eitherDecode body of
          Left e -> pure $ Left $ ControlProtocolError $ T.pack e
          Right r -> pure $ Right r
        else pure $ Left $ ControlConnectionError $
          "HTTP " <> T.pack (show status) <> ": " <> TE.decodeUtf8 (LBS.toStrict body)
