{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

{- |
Module      : Tsnet.Network.Packet
Description : IP packet handling for userspace networking
License     : BSD-3-Clause

This module provides basic IP packet parsing and construction for
the userspace network stack.
-}
module Tsnet.Network.Packet (
  -- * IP Packets
  IPVersion (..),
  IPPacket (..),
  IPv4Header (..),
  IPv6Header (..),
  Protocol (..),

  -- * Parsing
  parseIPPacket,
  serializeIPPacket,

  -- * TCP/UDP Headers
  TCPHeader (..),
  UDPHeader (..),
  parseTCPHeader,
  parseUDPHeader,

  -- * Utilities
  ipv4ToText,
  ipv6ToText,
  textToIPv4,
  textToIPv6,
) where

import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word16, Word32, Word8)
import Numeric (showHex)

-- | IP version
data IPVersion = IPv4 | IPv6
  deriving (Eq, Show)

-- | Protocol number
data Protocol
  = -- | 1
    ProtocolICMP
  | -- | 6
    ProtocolTCP
  | -- | 17
    ProtocolUDP
  | -- | 58
    ProtocolICMPv6
  | ProtocolOther !Word8
  deriving (Eq, Show)

protocolFromWord8 :: Word8 -> Protocol
protocolFromWord8 1 = ProtocolICMP
protocolFromWord8 6 = ProtocolTCP
protocolFromWord8 17 = ProtocolUDP
protocolFromWord8 58 = ProtocolICMPv6
protocolFromWord8 n = ProtocolOther n

protocolToWord8 :: Protocol -> Word8
protocolToWord8 ProtocolICMP = 1
protocolToWord8 ProtocolTCP = 6
protocolToWord8 ProtocolUDP = 17
protocolToWord8 ProtocolICMPv6 = 58
protocolToWord8 (ProtocolOther n) = n

-- | IPv4 header
data IPv4Header = IPv4Header
  { v4Version :: !Word8
  -- ^ Always 4
  , v4IHL :: !Word8
  -- ^ Header length in 32-bit words
  , v4DSCP :: !Word8
  -- ^ Differentiated Services
  , v4ECN :: !Word8
  -- ^ Explicit Congestion Notification
  , v4TotalLength :: !Word16
  -- ^ Total packet length
  , v4ID :: !Word16
  -- ^ Identification
  , v4Flags :: !Word8
  -- ^ Flags (3 bits)
  , v4FragOffset :: !Word16
  -- ^ Fragment offset (13 bits)
  , v4TTL :: !Word8
  -- ^ Time to live
  , v4Protocol :: !Protocol
  -- ^ Protocol
  , v4Checksum :: !Word16
  -- ^ Header checksum
  , v4SrcAddr :: !Word32
  -- ^ Source address
  , v4DstAddr :: !Word32
  -- ^ Destination address
  }
  deriving (Eq, Show)

-- | IPv6 header
data IPv6Header = IPv6Header
  { v6Version :: !Word8
  -- ^ Always 6
  , v6TrafficClass :: !Word8
  -- ^ Traffic class
  , v6FlowLabel :: !Word32
  -- ^ Flow label (20 bits)
  , v6PayloadLen :: !Word16
  -- ^ Payload length
  , v6NextHeader :: !Protocol
  -- ^ Next header (protocol)
  , v6HopLimit :: !Word8
  -- ^ Hop limit (TTL equivalent)
  , v6SrcAddr :: !ByteString
  -- ^ Source address (16 bytes)
  , v6DstAddr :: !ByteString
  -- ^ Destination address (16 bytes)
  }
  deriving (Eq, Show)

-- | Parsed IP packet
data IPPacket
  = -- | IPv4 packet with payload
    IPPacketV4 !IPv4Header !ByteString
  | -- | IPv6 packet with payload
    IPPacketV6 !IPv6Header !ByteString
  deriving (Eq, Show)

-- | TCP header (simplified, first 20 bytes)
data TCPHeader = TCPHeader
  { tcpSrcPort :: !Word16
  , tcpDstPort :: !Word16
  , tcpSeqNum :: !Word32
  , tcpAckNum :: !Word32
  , tcpDataOffset :: !Word8
  -- ^ Header length in 32-bit words
  , tcpFlags :: !Word16
  -- ^ Control flags
  , tcpWindow :: !Word16
  , tcpChecksum :: !Word16
  , tcpUrgent :: !Word16
  }
  deriving (Eq, Show)

-- | UDP header
data UDPHeader = UDPHeader
  { udpSrcPort :: !Word16
  , udpDstPort :: !Word16
  , udpLength :: !Word16
  , udpChecksum :: !Word16
  }
  deriving (Eq, Show)

--------------------------------------------------------------------------------
-- Parsing
--------------------------------------------------------------------------------

-- | Parse an IP packet
parseIPPacket :: ByteString -> Either String IPPacket
parseIPPacket bs
  | BS.length bs < 1 = Left "Packet too short"
  | otherwise =
      let version = (BS.index bs 0 `shiftR` 4) .&. 0x0F
       in case version of
            4 -> parseIPv4Packet bs
            6 -> parseIPv6Packet bs
            _ -> Left $ "Unknown IP version: " ++ show version

parseIPv4Packet :: ByteString -> Either String IPPacket
parseIPv4Packet bs
  | BS.length bs < 20 = Left "IPv4 packet too short"
  | otherwise =
      let b0 = BS.index bs 0
          version = (b0 `shiftR` 4) .&. 0x0F
          ihl = b0 .&. 0x0F
          headerLen = fromIntegral ihl * 4

          dscp = (BS.index bs 1 `shiftR` 2) .&. 0x3F
          ecn = BS.index bs 1 .&. 0x03
          totalLen = getWord16BE bs 2
          ident = getWord16BE bs 4
          flagsFrag = getWord16BE bs 6
          flags = fromIntegral $ (flagsFrag `shiftR` 13) .&. 0x07
          fragOffset = flagsFrag .&. 0x1FFF
          ttl = BS.index bs 8
          proto = protocolFromWord8 $ BS.index bs 9
          checksum = getWord16BE bs 10
          srcAddr = getWord32BE bs 12
          dstAddr = getWord32BE bs 16

          header =
            IPv4Header
              { v4Version = version
              , v4IHL = ihl
              , v4DSCP = dscp
              , v4ECN = ecn
              , v4TotalLength = totalLen
              , v4ID = ident
              , v4Flags = flags
              , v4FragOffset = fragOffset
              , v4TTL = ttl
              , v4Protocol = proto
              , v4Checksum = checksum
              , v4SrcAddr = srcAddr
              , v4DstAddr = dstAddr
              }

          payload = BS.drop headerLen bs
       in Right $ IPPacketV4 header payload

parseIPv6Packet :: ByteString -> Either String IPPacket
parseIPv6Packet bs
  | BS.length bs < 40 = Left "IPv6 packet too short"
  | otherwise =
      let b0 = getWord32BE bs 0
          version = fromIntegral $ (b0 `shiftR` 28) .&. 0x0F
          trafficClass = fromIntegral $ (b0 `shiftR` 20) .&. 0xFF
          flowLabel = b0 .&. 0xFFFFF
          payloadLen = getWord16BE bs 4
          nextHeader = protocolFromWord8 $ BS.index bs 6
          hopLimit = BS.index bs 7
          srcAddr = BS.take 16 $ BS.drop 8 bs
          dstAddr = BS.take 16 $ BS.drop 24 bs

          header =
            IPv6Header
              { v6Version = version
              , v6TrafficClass = trafficClass
              , v6FlowLabel = flowLabel
              , v6PayloadLen = payloadLen
              , v6NextHeader = nextHeader
              , v6HopLimit = hopLimit
              , v6SrcAddr = srcAddr
              , v6DstAddr = dstAddr
              }

          payload = BS.drop 40 bs
       in Right $ IPPacketV6 header payload

-- | Serialize an IP packet
serializeIPPacket :: IPPacket -> ByteString
serializeIPPacket (IPPacketV4 header payload) =
  serializeIPv4Header header <> payload
serializeIPPacket (IPPacketV6 header payload) =
  serializeIPv6Header header <> payload

serializeIPv4Header :: IPv4Header -> ByteString
serializeIPv4Header IPv4Header{..} =
  BS.pack
    [ (v4Version `shiftL` 4) .|. v4IHL
    , (v4DSCP `shiftL` 2) .|. v4ECN
    ]
    <> putWord16BE v4TotalLength
    <> putWord16BE v4ID
    <> putWord16BE ((fromIntegral v4Flags `shiftL` 13) .|. v4FragOffset)
    <> BS.pack [v4TTL, protocolToWord8 v4Protocol]
    <> putWord16BE v4Checksum
    <> putWord32BE v4SrcAddr
    <> putWord32BE v4DstAddr

serializeIPv6Header :: IPv6Header -> ByteString
serializeIPv6Header IPv6Header{..} =
  let firstWord =
        (fromIntegral v6Version `shiftL` 28)
          .|. (fromIntegral v6TrafficClass `shiftL` 20)
          .|. v6FlowLabel
   in putWord32BE firstWord
        <> putWord16BE v6PayloadLen
        <> BS.pack [protocolToWord8 v6NextHeader, v6HopLimit]
        <> v6SrcAddr
        <> v6DstAddr

-- | Parse TCP header
parseTCPHeader :: ByteString -> Either String TCPHeader
parseTCPHeader bs
  | BS.length bs < 20 = Left "TCP header too short"
  | otherwise =
      Right
        TCPHeader
          { tcpSrcPort = getWord16BE bs 0
          , tcpDstPort = getWord16BE bs 2
          , tcpSeqNum = getWord32BE bs 4
          , tcpAckNum = getWord32BE bs 8
          , tcpDataOffset = (BS.index bs 12 `shiftR` 4) .&. 0x0F
          , tcpFlags = getWord16BE bs 12 .&. 0x01FF
          , tcpWindow = getWord16BE bs 14
          , tcpChecksum = getWord16BE bs 16
          , tcpUrgent = getWord16BE bs 18
          }

-- | Parse UDP header
parseUDPHeader :: ByteString -> Either String UDPHeader
parseUDPHeader bs
  | BS.length bs < 8 = Left "UDP header too short"
  | otherwise =
      Right
        UDPHeader
          { udpSrcPort = getWord16BE bs 0
          , udpDstPort = getWord16BE bs 2
          , udpLength = getWord16BE bs 4
          , udpChecksum = getWord16BE bs 6
          }

--------------------------------------------------------------------------------
-- Address Utilities
--------------------------------------------------------------------------------

-- | Convert IPv4 address (Word32) to text
ipv4ToText :: Word32 -> Text
ipv4ToText addr =
  let b0 = (addr `shiftR` 24) .&. 0xFF
      b1 = (addr `shiftR` 16) .&. 0xFF
      b2 = (addr `shiftR` 8) .&. 0xFF
      b3 = addr .&. 0xFF
   in T.pack $ show b0 ++ "." ++ show b1 ++ "." ++ show b2 ++ "." ++ show b3

-- | Convert IPv6 address (ByteString) to text
ipv6ToText :: ByteString -> Text
ipv6ToText bs
  | BS.length bs /= 16 = "invalid-ipv6"
  | otherwise =
      let groups = [getWord16BE bs (i * 2) | i <- [0 .. 7]]
          hexGroups = map (\w -> T.pack $ showHex w "") groups
       in T.intercalate ":" hexGroups

-- | Parse IPv4 text to Word32
textToIPv4 :: Text -> Maybe Word32
textToIPv4 t =
  let parts = T.splitOn "." t
   in if length parts /= 4
        then Nothing
        else case mapM (readMaybe . T.unpack) parts of
          Nothing -> Nothing
          Just [a, b, c, d]
            | all (<= 255) [a, b, c, d] ->
                Just $ (a `shiftL` 24) .|. (b `shiftL` 16) .|. (c `shiftL` 8) .|. d
            | otherwise -> Nothing
          Just _ -> Nothing
 where
  readMaybe s = case reads s of
    [(x, "")] -> Just x
    _ -> Nothing

-- | Parse IPv6 text to ByteString (simplified)
textToIPv6 :: Text -> Maybe ByteString
textToIPv6 t =
  let parts = T.splitOn ":" t
   in if length parts /= 8
        then Nothing
        else case mapM (readHexMaybe . T.unpack) parts of
          Nothing -> Nothing
          Just words16
            | all (<= 0xFFFF) words16 -> Just $ BS.concat $ map putWord16BE words16
            | otherwise -> Nothing
 where
  readHexMaybe s = case reads ("0x" ++ s) of
    [(x, "")] -> Just x
    _ -> Nothing

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

getWord16BE :: ByteString -> Int -> Word16
getWord16BE bs offset =
  let b0 = fromIntegral $ BS.index bs offset
      b1 = fromIntegral $ BS.index bs (offset + 1)
   in (b0 `shiftL` 8) .|. b1

getWord32BE :: ByteString -> Int -> Word32
getWord32BE bs offset =
  let b0 = fromIntegral $ BS.index bs offset
      b1 = fromIntegral $ BS.index bs (offset + 1)
      b2 = fromIntegral $ BS.index bs (offset + 2)
      b3 = fromIntegral $ BS.index bs (offset + 3)
   in (b0 `shiftL` 24) .|. (b1 `shiftL` 16) .|. (b2 `shiftL` 8) .|. b3

putWord16BE :: Word16 -> ByteString
putWord16BE w =
  BS.pack
    [ fromIntegral ((w `shiftR` 8) .&. 0xFF)
    , fromIntegral (w .&. 0xFF)
    ]

putWord32BE :: Word32 -> ByteString
putWord32BE w =
  BS.pack
    [ fromIntegral ((w `shiftR` 24) .&. 0xFF)
    , fromIntegral ((w `shiftR` 16) .&. 0xFF)
    , fromIntegral ((w `shiftR` 8) .&. 0xFF)
    , fromIntegral (w .&. 0xFF)
    ]
