{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- |
-- Module      : Tailscale.DERP.Protocol
-- Description : DERP (Detour Encrypted Relay Protocol) implementation
-- License     : BSD-3-Clause
--
-- DERP is Tailscale's relay protocol for NAT traversal. When direct
-- peer-to-peer connections cannot be established, traffic is relayed
-- through DERP servers.
--
-- The protocol runs over HTTP/HTTPS with an upgrade to a custom
-- binary framing protocol.
--
-- = Frame Format
--
-- All frames have the format:
--
-- @
-- Type (1 byte) | Length (4 bytes, big-endian) | Payload
-- @
module Tailscale.DERP.Protocol
  ( -- * Frame Types
    FrameType (..)
  , Frame (..)

    -- * Frame Parsing
  , parseFrame
  , serializeFrame

    -- * Specific Frames
  , ServerKey (..)
  , ClientInfo (..)
  , RecvPacket (..)
  , SendPacket (..)
  , PeerGone (..)
  , PeerPresent (..)
  , WatchConns (..)
  , ClosePeer (..)
  , Ping (..)
  , Pong (..)
  , Health (..)
  , Restarting (..)

    -- * Constants
  , protocolVersion
  , maxFrameSize
  , preferredDERPRegions

    -- * Utilities
  , frameTypeFromByte
  , frameTypeToByte
  ) where

import Data.Bits (shiftL, shiftR, (.|.), (.&.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Word (Word8, Word32)

import Tailscale.WireGuard.Crypto (PublicKey(..))

-- | DERP protocol version
protocolVersion :: Int
protocolVersion = 2

-- | Maximum frame size (64 KB)
maxFrameSize :: Int
maxFrameSize = 64 * 1024

-- | Preferred DERP regions for Tailscale
preferredDERPRegions :: [(Int, Text, Text)]
preferredDERPRegions =
  [ (1, "nyc", "New York City")
  , (2, "sfo", "San Francisco")
  , (3, "sin", "Singapore")
  , (4, "fra", "Frankfurt")
  , (5, "syd", "Sydney")
  , (6, "blr", "Bangalore")
  , (7, "tok", "Tokyo")
  , (8, "lhr", "London")
  , (9, "dfw", "Dallas")
  , (10, "sea", "Seattle")
  , (11, "sao", "São Paulo")
  , (12, "par", "Paris")
  ]

-- | DERP frame types
data FrameType
  = FrameServerKey        -- ^ 0x01: Server sends its public key
  | FrameClientInfo       -- ^ 0x02: Client sends its info
  | FrameServerInfo       -- ^ 0x03: Server sends its info
  | FrameSendPacket       -- ^ 0x04: Client sends a packet to a peer
  | FrameRecvPacket       -- ^ 0x05: Server forwards a packet from a peer
  | FrameKeepAlive        -- ^ 0x06: Keep-alive frame
  | FrameNotePreferred    -- ^ 0x07: Client notes this server is preferred
  | FramePeerGone         -- ^ 0x08: Server notifies a peer disconnected
  | FramePeerPresent      -- ^ 0x09: Server notifies a peer connected
  | FrameWatchConns       -- ^ 0x0a: Client wants peer notifications
  | FrameClosePeer        -- ^ 0x0b: Server tells client to close peer conn
  | FramePing             -- ^ 0x0c: Ping frame
  | FramePong             -- ^ 0x0d: Pong frame
  | FrameHealth           -- ^ 0x0e: Health check frame
  | FrameRestarting       -- ^ 0x0f: Server is restarting
  | FrameForwardPacket    -- ^ 0x10: Forward packet with source info
  deriving (Eq, Show, Enum, Bounded)

frameTypeToByte :: FrameType -> Word8
frameTypeToByte FrameServerKey     = 0x01
frameTypeToByte FrameClientInfo    = 0x02
frameTypeToByte FrameServerInfo    = 0x03
frameTypeToByte FrameSendPacket    = 0x04
frameTypeToByte FrameRecvPacket    = 0x05
frameTypeToByte FrameKeepAlive     = 0x06
frameTypeToByte FrameNotePreferred = 0x07
frameTypeToByte FramePeerGone      = 0x08
frameTypeToByte FramePeerPresent   = 0x09
frameTypeToByte FrameWatchConns    = 0x0a
frameTypeToByte FrameClosePeer     = 0x0b
frameTypeToByte FramePing          = 0x0c
frameTypeToByte FramePong          = 0x0d
frameTypeToByte FrameHealth        = 0x0e
frameTypeToByte FrameRestarting    = 0x0f
frameTypeToByte FrameForwardPacket = 0x10

frameTypeFromByte :: Word8 -> Maybe FrameType
frameTypeFromByte 0x01 = Just FrameServerKey
frameTypeFromByte 0x02 = Just FrameClientInfo
frameTypeFromByte 0x03 = Just FrameServerInfo
frameTypeFromByte 0x04 = Just FrameSendPacket
frameTypeFromByte 0x05 = Just FrameRecvPacket
frameTypeFromByte 0x06 = Just FrameKeepAlive
frameTypeFromByte 0x07 = Just FrameNotePreferred
frameTypeFromByte 0x08 = Just FramePeerGone
frameTypeFromByte 0x09 = Just FramePeerPresent
frameTypeFromByte 0x0a = Just FrameWatchConns
frameTypeFromByte 0x0b = Just FrameClosePeer
frameTypeFromByte 0x0c = Just FramePing
frameTypeFromByte 0x0d = Just FramePong
frameTypeFromByte 0x0e = Just FrameHealth
frameTypeFromByte 0x0f = Just FrameRestarting
frameTypeFromByte 0x10 = Just FrameForwardPacket
frameTypeFromByte _    = Nothing

-- | A DERP frame
data Frame
  = FServerKey ServerKey
  | FClientInfo ClientInfo
  | FSendPacket SendPacket
  | FRecvPacket RecvPacket
  | FKeepAlive
  | FNotePreferred
  | FPeerGone PeerGone
  | FPeerPresent PeerPresent
  | FWatchConns WatchConns
  | FClosePeer ClosePeer
  | FPing Ping
  | FPong Pong
  | FHealth Health
  | FRestarting Restarting
  | FForwardPacket SendPacket ByteString  -- ^ Packet + source key
  deriving (Eq, Show)

-- | Server's public key (32 bytes)
newtype ServerKey = ServerKey { unServerKey :: ByteString }
  deriving (Eq, Show)

-- | Client information
data ClientInfo = ClientInfo
  { ciVersion    :: !Int
  , ciMeshKey    :: !(Maybe ByteString)  -- ^ 32 bytes if present
  , ciCanAckPings :: !Bool
  , ciIsProber   :: !Bool
  }
  deriving (Eq, Show)

-- | Received packet (from another peer via DERP)
data RecvPacket = RecvPacket
  { rpSourceKey :: !ByteString   -- ^ 32-byte public key of sender
  , rpData      :: !ByteString   -- ^ Packet data
  }
  deriving (Eq, Show)

-- | Send packet (to another peer via DERP)
data SendPacket = SendPacket
  { spDestKey :: !ByteString     -- ^ 32-byte public key of recipient
  , spData    :: !ByteString     -- ^ Packet data
  }
  deriving (Eq, Show)

-- | Peer disconnected notification
newtype PeerGone = PeerGone { pgKey :: ByteString }
  deriving (Eq, Show)

-- | Peer connected notification
newtype PeerPresent = PeerPresent { ppKey :: ByteString }
  deriving (Eq, Show)

-- | Request to watch for peer connections
data WatchConns = WatchConns
  deriving (Eq, Show)

-- | Request to close connection to peer
newtype ClosePeer = ClosePeer { cpKey :: ByteString }
  deriving (Eq, Show)

-- | Ping frame (8-byte data for echo)
newtype Ping = Ping { pingData :: ByteString }
  deriving (Eq, Show)

-- | Pong frame (echoes ping data)
newtype Pong = Pong { pongData :: ByteString }
  deriving (Eq, Show)

-- | Health check message
newtype Health = Health { healthMessage :: Text }
  deriving (Eq, Show)

-- | Server restarting notification
data Restarting = Restarting
  { restartReconnectIn :: !Word32  -- ^ Milliseconds until reconnect
  , restartTryFor      :: !Word32  -- ^ How long to try reconnecting (ms)
  }
  deriving (Eq, Show)

--------------------------------------------------------------------------------
-- Frame Parsing
--------------------------------------------------------------------------------

-- | Parse a frame from bytes
--
-- Returns (frame, remaining bytes) or error
parseFrame :: ByteString -> Either String (Frame, ByteString)
parseFrame bs
  | BS.length bs < 5 = Left "Frame too short for header"
  | otherwise =
      let frameType = BS.index bs 0
          len = getWord32BE bs 1
      in if fromIntegral len > maxFrameSize
           then Left "Frame too large"
           else if BS.length bs < 5 + fromIntegral len
             then Left "Incomplete frame"
             else case frameTypeFromByte frameType of
               Nothing -> Left $ "Unknown frame type: " ++ show frameType
               Just ft -> do
                 let payload = BS.take (fromIntegral len) $ BS.drop 5 bs
                     rest = BS.drop (5 + fromIntegral len) bs
                 frame <- parseFramePayload ft payload
                 Right (frame, rest)

-- | Parse frame payload based on type
parseFramePayload :: FrameType -> ByteString -> Either String Frame
parseFramePayload FrameServerKey payload
  | BS.length payload /= 32 = Left "Invalid server key length"
  | otherwise = Right $ FServerKey $ ServerKey payload

parseFramePayload FrameSendPacket payload
  | BS.length payload < 32 = Left "Send packet too short"
  | otherwise =
      let destKey = BS.take 32 payload
          pktData = BS.drop 32 payload
      in Right $ FSendPacket $ SendPacket destKey pktData

parseFramePayload FrameRecvPacket payload
  | BS.length payload < 32 = Left "Recv packet too short"
  | otherwise =
      let srcKey = BS.take 32 payload
          pktData = BS.drop 32 payload
      in Right $ FRecvPacket $ RecvPacket srcKey pktData

parseFramePayload FrameKeepAlive _ = Right FKeepAlive

parseFramePayload FrameNotePreferred _ = Right FNotePreferred

parseFramePayload FramePeerGone payload
  | BS.length payload /= 32 = Left "Invalid peer gone length"
  | otherwise = Right $ FPeerGone $ PeerGone payload

parseFramePayload FramePeerPresent payload
  | BS.length payload /= 32 = Left "Invalid peer present length"
  | otherwise = Right $ FPeerPresent $ PeerPresent payload

parseFramePayload FrameWatchConns _ = Right $ FWatchConns WatchConns

parseFramePayload FrameClosePeer payload
  | BS.length payload /= 32 = Left "Invalid close peer length"
  | otherwise = Right $ FClosePeer $ ClosePeer payload

parseFramePayload FramePing payload = Right $ FPing $ Ping payload

parseFramePayload FramePong payload = Right $ FPong $ Pong payload

parseFramePayload FrameHealth payload =
  Right $ FHealth $ Health $ TE.decodeUtf8 payload

parseFramePayload FrameRestarting payload
  | BS.length payload < 8 = Left "Restarting frame too short"
  | otherwise =
      let reconnectIn = getWord32BE payload 0
          tryFor = getWord32BE payload 4
      in Right $ FRestarting $ Restarting reconnectIn tryFor

parseFramePayload FrameForwardPacket payload
  | BS.length payload < 64 = Left "Forward packet too short"
  | otherwise =
      let srcKey = BS.take 32 payload
          destKey = BS.take 32 $ BS.drop 32 payload
          pktData = BS.drop 64 payload
      in Right $ FForwardPacket (SendPacket destKey pktData) srcKey

parseFramePayload FrameClientInfo _ = Left "Unexpected ClientInfo frame from server"
parseFramePayload FrameServerInfo _ = Left "ServerInfo not implemented"

-- | Serialize a frame to bytes
serializeFrame :: Frame -> ByteString
serializeFrame (FServerKey (ServerKey key)) =
  mkFrame FrameServerKey key

serializeFrame (FClientInfo ClientInfo{..}) =
  let payload = BS.concat
        [ putWord8 (fromIntegral ciVersion)
        , case ciMeshKey of
            Nothing -> BS.singleton 0
            Just k  -> BS.singleton 1 <> k
        , if ciCanAckPings then BS.singleton 1 else BS.singleton 0
        , if ciIsProber then BS.singleton 1 else BS.singleton 0
        ]
  in mkFrame FrameClientInfo payload

serializeFrame (FSendPacket (SendPacket destKey pktData)) =
  mkFrame FrameSendPacket (destKey <> pktData)

serializeFrame (FRecvPacket (RecvPacket srcKey pktData)) =
  mkFrame FrameRecvPacket (srcKey <> pktData)

serializeFrame FKeepAlive = mkFrame FrameKeepAlive ""

serializeFrame FNotePreferred = mkFrame FrameNotePreferred ""

serializeFrame (FPeerGone (PeerGone key)) =
  mkFrame FramePeerGone key

serializeFrame (FPeerPresent (PeerPresent key)) =
  mkFrame FramePeerPresent key

serializeFrame (FWatchConns _) = mkFrame FrameWatchConns ""

serializeFrame (FClosePeer (ClosePeer key)) =
  mkFrame FrameClosePeer key

serializeFrame (FPing (Ping d)) = mkFrame FramePing d

serializeFrame (FPong (Pong d)) = mkFrame FramePong d

serializeFrame (FHealth (Health msg)) =
  mkFrame FrameHealth (TE.encodeUtf8 msg)

serializeFrame (FRestarting (Restarting reconnect tryFor)) =
  mkFrame FrameRestarting (putWord32BE reconnect <> putWord32BE tryFor)

serializeFrame (FForwardPacket (SendPacket destKey pktData) srcKey) =
  mkFrame FrameForwardPacket (srcKey <> destKey <> pktData)

-- | Make a frame with type and payload
mkFrame :: FrameType -> ByteString -> ByteString
mkFrame ft payload =
  BS.singleton (frameTypeToByte ft) <> putWord32BE (fromIntegral $ BS.length payload) <> payload

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

getWord32BE :: ByteString -> Int -> Word32
getWord32BE bs offset =
  let b0 = fromIntegral $ BS.index bs offset
      b1 = fromIntegral $ BS.index bs (offset + 1)
      b2 = fromIntegral $ BS.index bs (offset + 2)
      b3 = fromIntegral $ BS.index bs (offset + 3)
  in (b0 `shiftL` 24) .|. (b1 `shiftL` 16) .|. (b2 `shiftL` 8) .|. b3

putWord32BE :: Word32 -> ByteString
putWord32BE w = BS.pack
  [ fromIntegral ((w `shiftR` 24) .&. 0xFF)
  , fromIntegral ((w `shiftR` 16) .&. 0xFF)
  , fromIntegral ((w `shiftR` 8) .&. 0xFF)
  , fromIntegral (w .&. 0xFF)
  ]

putWord8 :: Word8 -> ByteString
putWord8 = BS.singleton
