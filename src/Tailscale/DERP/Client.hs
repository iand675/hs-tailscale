{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- |
-- Module      : Tailscale.DERP.Client
-- Description : DERP client implementation
-- License     : BSD-3-Clause
--
-- This module provides a client for connecting to DERP servers and
-- relaying WireGuard packets through them.
module Tailscale.DERP.Client
  ( -- * Client
    DERPClient (..)
  , DERPConfig (..)
  , DERPError (..)

    -- * Connection
  , newDERPClient
  , connectDERP
  , closeDERP
  , withDERP

    -- * Communication
  , sendPacket
  , recvPacket
  , sendKeepAlive
  , notePreferred

    -- * Server Info
  , derpRegionURL
  ) where

import Control.Concurrent (forkIO, threadDelay, killThread, ThreadId)
import Control.Concurrent.MVar
import Control.Concurrent.STM
import Control.Exception (try, SomeException)
import Control.Monad (when, void)
import Data.Bits (shiftL, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word32)
import Network.Socket (Socket)
import qualified Network.Socket as Socket
import qualified Network.Socket.ByteString as SBS

import Tailscale.DERP.Protocol
import Tailscale.WireGuard.Crypto (PrivateKey, PublicKey, derivePublicKey)

-- | DERP client errors
data DERPError
  = DERPConnectionFailed !Text
  | DERPHandshakeFailed !Text
  | DERPFrameError !Text
  | DERPClosed
  deriving (Eq, Show)

-- | Configuration for DERP client
data DERPConfig = DERPConfig
  { dcRegionID    :: !Int
    -- ^ DERP region ID
  , dcServerURL   :: !Text
    -- ^ Full URL to DERP server (e.g., "https://derp1.tailscale.com")
  , dcPrivateKey  :: !PrivateKey
    -- ^ Our private key for authentication
  , dcCanAckPings :: !Bool
    -- ^ Whether we can acknowledge pings
  }
  deriving (Show)

-- | DERP client state
data DERPClient = DERPClient
  { dcSocket      :: !(MVar Socket)
  , dcServerKey   :: !(MVar ByteString)
  , dcConfig      :: !DERPConfig
  , dcPublicKey   :: !PublicKey
  , dcRecvQueue   :: !(TQueue RecvPacket)
  , dcClosed      :: !(IORef Bool)
  , dcReadThread  :: !(MVar (Maybe ThreadId))
  }

-- | Get the URL for a DERP region
derpRegionURL :: Int -> Text
derpRegionURL regionID = "https://derp" <> T.pack (show regionID) <> ".tailscale.com"

-- | Create a new DERP client (not yet connected)
newDERPClient :: DERPConfig -> IO DERPClient
newDERPClient config = do
  socket <- newEmptyMVar
  serverKey <- newEmptyMVar
  recvQueue <- newTQueueIO
  closed <- newIORef False
  readThread <- newMVar Nothing
  pure DERPClient
    { dcSocket = socket
    , dcServerKey = serverKey
    , dcConfig = config
    , dcPublicKey = derivePublicKey (dcPrivateKey config)
    , dcRecvQueue = recvQueue
    , dcClosed = closed
    , dcReadThread = readThread
    }

-- | Connect to the DERP server
connectDERP :: DERPClient -> IO (Either DERPError ())
connectDERP client = do
  writeIORef (dcClosed client) False

  -- For now, we'll do a simplified connection
  -- In reality, this should do HTTP upgrade to DERP protocol
  result <- try $ do
    -- Parse the URL and extract host/port
    let url = dcServerURL (dcConfig client)
        -- Extract hostname (simplified)
        host = T.unpack $ T.drop 8 $ T.takeWhile (/= '/') $ T.drop 8 url  -- after "https://"
        port = "443"

    -- Resolve and connect
    addrInfos <- Socket.getAddrInfo
      (Just Socket.defaultHints { Socket.addrSocketType = Socket.Stream })
      (Just host)
      (Just port)

    case addrInfos of
      [] -> error "Could not resolve DERP server"
      (addr:_) -> do
        sock <- Socket.socket
          (Socket.addrFamily addr)
          (Socket.addrSocketType addr)
          (Socket.addrProtocol addr)
        Socket.connect sock (Socket.addrAddress addr)

        -- Store socket
        putMVar (dcSocket client) sock

        -- TODO: Proper TLS and HTTP upgrade handshake
        -- For now, we'll just note that this needs to be done

        -- Start reader thread
        tid <- forkIO $ readerLoop client
        modifyMVar_ (dcReadThread client) $ \_ -> pure (Just tid)

        pure ()

  case result of
    Left (e :: SomeException) ->
      pure $ Left $ DERPConnectionFailed $ T.pack $ show e
    Right () ->
      pure $ Right ()

-- | Reader loop for incoming frames
readerLoop :: DERPClient -> IO ()
readerLoop client = do
  closed <- readIORef (dcClosed client)
  when (not closed) $ do
    mSock <- tryReadMVar (dcSocket client)
    case mSock of
      Nothing -> threadDelay 100000  -- 100ms
      Just sock -> do
        -- Read frame header (5 bytes: type + length)
        headerResult <- try $ SBS.recv sock 5
        case headerResult of
          Left (_ :: SomeException) -> do
            writeIORef (dcClosed client) True
          Right header
            | BS.length header < 5 -> do
                writeIORef (dcClosed client) True
            | otherwise -> do
                let frameLen = fromIntegral $ getWord32BE header 1
                payload <- SBS.recv sock frameLen
                let fullFrame = header <> payload
                case parseFrame fullFrame of
                  Left _ -> pure ()  -- Skip bad frames
                  Right (frame, _) -> handleFrame client frame

        readerLoop client

-- | Handle an incoming frame
handleFrame :: DERPClient -> Frame -> IO ()
handleFrame client frame = case frame of
  FServerKey (ServerKey key) ->
    void $ tryPutMVar (dcServerKey client) key

  FRecvPacket pkt ->
    atomically $ writeTQueue (dcRecvQueue client) pkt

  FPeerGone _ -> pure ()  -- Could track this
  FPeerPresent _ -> pure ()  -- Could track this

  FPing (Ping pingData) -> do
    -- Send pong back
    mSock <- tryReadMVar (dcSocket client)
    case mSock of
      Nothing -> pure ()
      Just sock -> do
        let pongFrame = serializeFrame (FPong (Pong pingData))
        void $ SBS.send sock pongFrame

  FHealth _ -> pure ()  -- Could log
  FRestarting _ -> pure ()  -- Could handle reconnect

  _ -> pure ()

-- | Close the DERP connection
closeDERP :: DERPClient -> IO ()
closeDERP client = do
  writeIORef (dcClosed client) True

  -- Kill reader thread
  mTid <- readMVar (dcReadThread client)
  case mTid of
    Nothing -> pure ()
    Just tid -> killThread tid

  -- Close socket
  mSock <- tryTakeMVar (dcSocket client)
  case mSock of
    Nothing -> pure ()
    Just sock -> Socket.close sock

-- | Run an action with a DERP client, ensuring cleanup
withDERP :: DERPConfig -> (DERPClient -> IO a) -> IO (Either DERPError a)
withDERP config action = do
  client <- newDERPClient config
  result <- connectDERP client
  case result of
    Left err -> pure $ Left err
    Right () -> do
      a <- action client
      closeDERP client
      pure $ Right a

-- | Send a packet to a peer via DERP
sendPacket :: DERPClient -> ByteString -> ByteString -> IO (Either DERPError ())
sendPacket client destKey payload = do
  closed <- readIORef (dcClosed client)
  if closed
    then pure $ Left DERPClosed
    else do
      mSock <- tryReadMVar (dcSocket client)
      case mSock of
        Nothing -> pure $ Left DERPClosed
        Just sock -> do
          let frame = serializeFrame $ FSendPacket $ SendPacket destKey payload
          result <- try $ SBS.sendAll sock frame
          case result of
            Left (_ :: SomeException) -> pure $ Left DERPClosed
            Right () -> pure $ Right ()

-- | Receive a packet from the queue
recvPacket :: DERPClient -> IO RecvPacket
recvPacket client = atomically $ readTQueue (dcRecvQueue client)

-- | Try to receive a packet (non-blocking)
tryRecvPacket :: DERPClient -> IO (Maybe RecvPacket)
tryRecvPacket client = atomically $ tryReadTQueue (dcRecvQueue client)

-- | Send a keepalive
sendKeepAlive :: DERPClient -> IO (Either DERPError ())
sendKeepAlive client = do
  closed <- readIORef (dcClosed client)
  if closed
    then pure $ Left DERPClosed
    else do
      mSock <- tryReadMVar (dcSocket client)
      case mSock of
        Nothing -> pure $ Left DERPClosed
        Just sock -> do
          let frame = serializeFrame FKeepAlive
          result <- try $ SBS.sendAll sock frame
          case result of
            Left (_ :: SomeException) -> pure $ Left DERPClosed
            Right () -> pure $ Right ()

-- | Note that this DERP server is our preferred server
notePreferred :: DERPClient -> IO (Either DERPError ())
notePreferred client = do
  closed <- readIORef (dcClosed client)
  if closed
    then pure $ Left DERPClosed
    else do
      mSock <- tryReadMVar (dcSocket client)
      case mSock of
        Nothing -> pure $ Left DERPClosed
        Just sock -> do
          let frame = serializeFrame FNotePreferred
          result <- try $ SBS.sendAll sock frame
          case result of
            Left (_ :: SomeException) -> pure $ Left DERPClosed
            Right () -> pure $ Right ()

-- | Helper to get Word32 from ByteString (big-endian)
getWord32BE :: ByteString -> Int -> Word32
getWord32BE bs offset =
  let b0 = fromIntegral $ BS.index bs offset
      b1 = fromIntegral $ BS.index bs (offset + 1)
      b2 = fromIntegral $ BS.index bs (offset + 2)
      b3 = fromIntegral $ BS.index bs (offset + 3)
  in (b0 `shiftL` 24) .|. (b1 `shiftL` 16) .|. (b2 `shiftL` 8) .|. b3
