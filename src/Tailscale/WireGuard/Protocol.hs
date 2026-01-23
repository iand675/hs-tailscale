{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

{- |
Module      : Tailscale.WireGuard.Protocol
Description : WireGuard protocol implementation
License     : BSD-3-Clause

This module implements the WireGuard protocol, including:

* Packet types (Handshake Init, Response, Cookie Reply, Transport Data)
* Session management
* Timer handling
* Packet encryption/decryption
-}
module Tailscale.WireGuard.Protocol (
  -- * Message Types
  MessageType (..),
  HandshakeInit (..),
  HandshakeResponse (..),
  CookieReply (..),
  TransportData (..),

  -- * Packet Parsing
  parseMessage,
  parseHandshakeInit,
  parseTransportData,
  serializeHandshakeInit,
  serializeHandshakeResponse,
  serializeTransportData,

  -- * Message Type Conversion
  messageTypeByte,
  messageTypeFromByte,

  -- * Session
  Session (..),
  SessionState (..),
  newSession,

  -- * Transport Encryption
  encryptTransport,
  decryptTransport,

  -- * Constants
  rekeyAfterMessages,
  rejectAfterMessages,
  rekeyAfterTime,
  rekeyAttemptTime,
  rekeyTimeout,
  keepaliveTimeout,
) where

import Control.Concurrent.STM
import Crypto.Error (CryptoFailable (..))
import qualified Crypto.PubKey.Curve25519 as X25519
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Time.Clock (NominalDiffTime, UTCTime)
import Data.Word (Word32, Word64, Word8)

import Tailscale.WireGuard.Crypto
import Tailscale.WireGuard.Noise

--------------------------------------------------------------------------------
-- Constants
--------------------------------------------------------------------------------

-- | Rekey after this many messages
rekeyAfterMessages :: Word64
rekeyAfterMessages = 2 ^ (60 :: Int) - 1

-- | Reject after this many messages
rejectAfterMessages :: Word64
rejectAfterMessages = 2 ^ (64 :: Int) - 2 ^ (4 :: Int) - 1

-- | Rekey after this many seconds
rekeyAfterTime :: NominalDiffTime
rekeyAfterTime = 120 -- 2 minutes

-- | Attempt rekey this many seconds before expiry
rekeyAttemptTime :: NominalDiffTime
rekeyAttemptTime = 90 -- 1.5 minutes

-- | Rekey timeout
rekeyTimeout :: NominalDiffTime
rekeyTimeout = 5

-- | Keepalive timeout
keepaliveTimeout :: NominalDiffTime
keepaliveTimeout = 10

--------------------------------------------------------------------------------
-- Message Types
--------------------------------------------------------------------------------

-- | WireGuard message type
data MessageType
  = -- | 1
    MsgTypeHandshakeInit
  | -- | 2
    MsgTypeHandshakeResponse
  | -- | 3
    MsgTypeCookieReply
  | -- | 4
    MsgTypeTransportData
  deriving (Eq, Show, Enum)

messageTypeByte :: MessageType -> Word8
messageTypeByte MsgTypeHandshakeInit = 1
messageTypeByte MsgTypeHandshakeResponse = 2
messageTypeByte MsgTypeCookieReply = 3
messageTypeByte MsgTypeTransportData = 4

messageTypeFromByte :: Word8 -> Maybe MessageType
messageTypeFromByte 1 = Just MsgTypeHandshakeInit
messageTypeFromByte 2 = Just MsgTypeHandshakeResponse
messageTypeFromByte 3 = Just MsgTypeCookieReply
messageTypeFromByte 4 = Just MsgTypeTransportData
messageTypeFromByte _ = Nothing

-- | Handshake initiation message (148 bytes)
data HandshakeInit = HandshakeInit
  { hiSenderIndex :: !Word32
  -- ^ Sender's session index
  , hiEphemeral :: !PublicKey
  -- ^ Ephemeral public key (32 bytes)
  , hiEncryptedStatic :: !ByteString
  -- ^ Encrypted static key (48 bytes)
  , hiEncryptedTimestamp :: !ByteString
  -- ^ Encrypted timestamp (28 bytes)
  , hiMac1 :: !ByteString
  -- ^ MAC1 (16 bytes)
  , hiMac2 :: !ByteString
  -- ^ MAC2 (16 bytes)
  }
  deriving (Eq, Show)

-- | Handshake response message (92 bytes)
data HandshakeResponse = HandshakeResponse
  { hrSenderIndex :: !Word32
  -- ^ Sender's session index
  , hrReceiverIndex :: !Word32
  -- ^ Receiver's session index
  , hrEphemeral :: !PublicKey
  -- ^ Ephemeral public key (32 bytes)
  , hrEncryptedNothing :: !ByteString
  -- ^ Encrypted empty (16 bytes)
  , hrMac1 :: !ByteString
  -- ^ MAC1 (16 bytes)
  , hrMac2 :: !ByteString
  -- ^ MAC2 (16 bytes)
  }
  deriving (Eq, Show)

-- | Cookie reply message (64 bytes)
data CookieReply = CookieReply
  { crReceiverIndex :: !Word32
  -- ^ Receiver's session index
  , crNonce :: !ByteString
  -- ^ Nonce (24 bytes)
  , crEncryptedCookie :: !ByteString
  -- ^ Encrypted cookie (32 bytes)
  }
  deriving (Eq, Show)

-- | Transport data message (variable length)
data TransportData = TransportData
  { tdReceiverIndex :: !Word32
  -- ^ Receiver's session index
  , tdCounter :: !Word64
  -- ^ Message counter
  , tdEncryptedPacket :: !ByteString
  -- ^ Encrypted IP packet
  }
  deriving (Eq, Show)

--------------------------------------------------------------------------------
-- Packet Parsing
--------------------------------------------------------------------------------

-- | Parse a WireGuard message
parseMessage :: ByteString -> Either String (MessageType, ByteString)
parseMessage bs
  | BS.length bs < 4 = Left "Message too short"
  | otherwise =
      let msgType = BS.index bs 0
          reserved = BS.take 3 $ BS.drop 1 bs
          payload = BS.drop 4 bs
       in if reserved /= "\0\0\0"
            then Left "Invalid reserved bytes"
            else case messageTypeFromByte msgType of
              Nothing -> Left $ "Unknown message type: " ++ show msgType
              Just mt -> Right (mt, payload)

-- | Parse a handshake init message
parseHandshakeInit :: ByteString -> Either String HandshakeInit
parseHandshakeInit bs
  | BS.length bs /= 144 = Left "Invalid handshake init length"
  | otherwise =
      let senderIndex = getWord32LE bs 0
          ephemeralBytes = BS.take 32 $ BS.drop 4 bs
          encStatic = BS.take 48 $ BS.drop 36 bs
          encTimestamp = BS.take 28 $ BS.drop 84 bs
          mac1 = BS.take 16 $ BS.drop 112 bs
          mac2 = BS.take 16 $ BS.drop 128 bs
       in Right
            HandshakeInit
              { hiSenderIndex = senderIndex
              , hiEphemeral = PublicKey $ throwCryptoError $ X25519.publicKey ephemeralBytes
              , hiEncryptedStatic = encStatic
              , hiEncryptedTimestamp = encTimestamp
              , hiMac1 = mac1
              , hiMac2 = mac2
              }
 where
  throwCryptoError (CryptoFailed _) = error "invalid public key"
  throwCryptoError (CryptoPassed x) = x

-- | Parse a transport data message
parseTransportData :: ByteString -> Either String TransportData
parseTransportData bs
  | BS.length bs < 16 = Left "Transport message too short"
  | otherwise =
      let receiverIndex = getWord32LE bs 0
          counter = getWord64LE bs 4
          encPacket = BS.drop 12 bs
       in Right
            TransportData
              { tdReceiverIndex = receiverIndex
              , tdCounter = counter
              , tdEncryptedPacket = encPacket
              }

-- | Serialize a handshake init message
serializeHandshakeInit :: HandshakeInit -> ByteString
serializeHandshakeInit HandshakeInit{..} =
  BS.concat
    [ BS.singleton 1
    , BS.replicate 3 0 -- Type and reserved
    , putWord32LE hiSenderIndex
    , pubKeyBytes hiEphemeral
    , hiEncryptedStatic
    , hiEncryptedTimestamp
    , hiMac1
    , hiMac2
    ]

-- | Serialize a handshake response message
serializeHandshakeResponse :: HandshakeResponse -> ByteString
serializeHandshakeResponse HandshakeResponse{..} =
  BS.concat
    [ BS.singleton 2
    , BS.replicate 3 0 -- Type and reserved
    , putWord32LE hrSenderIndex
    , putWord32LE hrReceiverIndex
    , pubKeyBytes hrEphemeral
    , hrEncryptedNothing
    , hrMac1
    , hrMac2
    ]

-- | Serialize a transport data message
serializeTransportData :: TransportData -> ByteString
serializeTransportData TransportData{..} =
  BS.concat
    [ BS.singleton 4
    , BS.replicate 3 0 -- Type and reserved
    , putWord32LE tdReceiverIndex
    , putWord64LE tdCounter
    , tdEncryptedPacket
    ]

--------------------------------------------------------------------------------
-- Session
--------------------------------------------------------------------------------

-- | Session state
data SessionState
  = SessionStateNew
  | SessionStateHandshakeInit
  | SessionStateHandshakeResponse
  | SessionStateEstablished
  deriving (Eq, Show)

-- | A WireGuard session with a peer
data Session = Session
  { sessLocalIndex :: !Word32
  , sessRemoteIndex :: !(Maybe Word32)
  , sessState :: !SessionState
  , sessKeys :: !(Maybe SessionKeys)
  , sessSendNonce :: !(TVar Word64)
  , sessRecvNonce :: !(TVar Word64)
  , sessCreated :: !UTCTime
  , sessLastSend :: !(TVar UTCTime)
  , sessLastRecv :: !(TVar UTCTime)
  }

-- | Create a new session
newSession :: Word32 -> UTCTime -> IO Session
newSession localIndex now = do
  sendNonce <- newTVarIO 0
  recvNonce <- newTVarIO 0
  lastSend <- newTVarIO now
  lastRecv <- newTVarIO now
  pure
    Session
      { sessLocalIndex = localIndex
      , sessRemoteIndex = Nothing
      , sessState = SessionStateNew
      , sessKeys = Nothing
      , sessSendNonce = sendNonce
      , sessRecvNonce = recvNonce
      , sessCreated = now
      , sessLastSend = lastSend
      , sessLastRecv = lastRecv
      }

--------------------------------------------------------------------------------
-- Transport Encryption
--------------------------------------------------------------------------------

-- | Encrypt a packet for transport
encryptTransport ::
  SessionKeys ->
  -- | Counter
  Word64 ->
  -- | Plaintext IP packet
  ByteString ->
  -- | Encrypted packet (without header)
  ByteString
encryptTransport keys counter plaintext =
  let key = csKey (skSend keys)
      nonce = nonceFromCounter counter
   in encrypt key nonce "" plaintext

-- | Decrypt a transport packet
decryptTransport ::
  SessionKeys ->
  -- | Counter
  Word64 ->
  -- | Encrypted packet
  ByteString ->
  -- | Decrypted IP packet
  Maybe ByteString
decryptTransport keys counter ciphertext =
  let key = csKey (skReceive keys)
      nonce = nonceFromCounter counter
   in decrypt key nonce "" ciphertext

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

-- | Get a little-endian Word32 from a ByteString
getWord32LE :: ByteString -> Int -> Word32
getWord32LE bs offset =
  let b0 = fromIntegral $ BS.index bs offset
      b1 = fromIntegral $ BS.index bs (offset + 1)
      b2 = fromIntegral $ BS.index bs (offset + 2)
      b3 = fromIntegral $ BS.index bs (offset + 3)
   in b0 .|. (b1 `shiftL` 8) .|. (b2 `shiftL` 16) .|. (b3 `shiftL` 24)

-- | Get a little-endian Word64 from a ByteString
getWord64LE :: ByteString -> Int -> Word64
getWord64LE bs offset =
  let b0 = fromIntegral $ BS.index bs offset
      b1 = fromIntegral $ BS.index bs (offset + 1)
      b2 = fromIntegral $ BS.index bs (offset + 2)
      b3 = fromIntegral $ BS.index bs (offset + 3)
      b4 = fromIntegral $ BS.index bs (offset + 4)
      b5 = fromIntegral $ BS.index bs (offset + 5)
      b6 = fromIntegral $ BS.index bs (offset + 6)
      b7 = fromIntegral $ BS.index bs (offset + 7)
   in b0
        .|. (b1 `shiftL` 8)
        .|. (b2 `shiftL` 16)
        .|. (b3 `shiftL` 24)
        .|. (b4 `shiftL` 32)
        .|. (b5 `shiftL` 40)
        .|. (b6 `shiftL` 48)
        .|. (b7 `shiftL` 56)

-- | Put a little-endian Word32
putWord32LE :: Word32 -> ByteString
putWord32LE w =
  BS.pack
    [ fromIntegral (w .&. 0xFF)
    , fromIntegral ((w `shiftR` 8) .&. 0xFF)
    , fromIntegral ((w `shiftR` 16) .&. 0xFF)
    , fromIntegral ((w `shiftR` 24) .&. 0xFF)
    ]

-- | Put a little-endian Word64
putWord64LE :: Word64 -> ByteString
putWord64LE w =
  BS.pack
    [ fromIntegral (w .&. 0xFF)
    , fromIntegral ((w `shiftR` 8) .&. 0xFF)
    , fromIntegral ((w `shiftR` 16) .&. 0xFF)
    , fromIntegral ((w `shiftR` 24) .&. 0xFF)
    , fromIntegral ((w `shiftR` 32) .&. 0xFF)
    , fromIntegral ((w `shiftR` 40) .&. 0xFF)
    , fromIntegral ((w `shiftR` 48) .&. 0xFF)
    , fromIntegral ((w `shiftR` 56) .&. 0xFF)
    ]

-- | Extract public key bytes
pubKeyBytes :: PublicKey -> ByteString
pubKeyBytes (PublicKey pk) = BA.convert pk
