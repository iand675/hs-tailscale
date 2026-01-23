{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

{- |
Module      : WireGuard.Protocol
Description : WireGuard protocol implementation
License     : BSD-3-Clause

This module implements the WireGuard protocol, including:

* Packet types (Handshake Init, Response, Cookie Reply, Transport Data)
* Session management
* Timer handling
* Packet encryption/decryption

The implementation follows the WireGuard protocol specification:
https://www.wireguard.com/protocol/
-}
module WireGuard.Protocol (
  -- * Message Types
  MessageType (..),
  HandshakeInit (..),
  HandshakeResponse (..),
  CookieReply (..),
  TransportData (..),

  -- * Packet Parsing
  parseMessage,
  parseHandshakeInit,
  parseHandshakeResponse,
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

  -- * MAC Computation
  computeMac1,
  computeMac2,
  mac1Label,
  mac2Label,
  cookieLabel,

  -- * Constants
  rekeyAfterMessages,
  rejectAfterMessages,
  rekeyAfterTime,
  rekeyAttemptTime,
  rekeyTimeout,
  keepaliveTimeout,
  handshakeInitLen,
  handshakeResponseLen,
  cookieReplyLen,
  transportHeaderLen,
) where

import Control.Concurrent.STM
import Crypto.Error (CryptoFailable (..))
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Time.Clock (NominalDiffTime, UTCTime)
import Data.Word (Word32, Word64, Word8)

import WireGuard.Bits
import WireGuard.Crypto
import WireGuard.Noise

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

-- | Length of handshake initiation message
handshakeInitLen :: Int
handshakeInitLen = 148

-- | Length of handshake response message
handshakeResponseLen :: Int
handshakeResponseLen = 92

-- | Length of cookie reply message
cookieReplyLen :: Int
cookieReplyLen = 64

-- | Length of transport data header (before encrypted packet)
transportHeaderLen :: Int
transportHeaderLen = 16

-- | MAC1 label for computing MAC1
mac1Label :: ByteString
mac1Label = "mac1----"

-- | MAC2 label for computing MAC2
mac2Label :: ByteString
mac2Label = "cookie--"

-- | Cookie label for computing cookie key
cookieLabel :: ByteString
cookieLabel = "cookie--"

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

-- | Handshake initiation message (148 bytes total)
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

-- | Handshake response message (92 bytes total)
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

-- | Cookie reply message (64 bytes total)
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

-- | Parse a WireGuard message header
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

-- | Parse a handshake init message (without the 4-byte header)
parseHandshakeInit :: ByteString -> Either String HandshakeInit
parseHandshakeInit bs
  | BS.length bs /= 144 = Left $ "Invalid handshake init length: " ++ show (BS.length bs) ++ " (expected 144)"
  | otherwise =
      let senderIndex = getWord32LE bs 0
          ephemeralBytes = BS.take 32 $ BS.drop 4 bs
          encStatic = BS.take 48 $ BS.drop 36 bs
          encTimestamp = BS.take 28 $ BS.drop 84 bs
          mac1 = BS.take 16 $ BS.drop 112 bs
          mac2 = BS.take 16 $ BS.drop 128 bs
       in case X25519.publicKey ephemeralBytes of
            CryptoFailed _ -> Left "Invalid ephemeral public key"
            CryptoPassed pk ->
              Right
                HandshakeInit
                  { hiSenderIndex = senderIndex
                  , hiEphemeral = PublicKey pk
                  , hiEncryptedStatic = encStatic
                  , hiEncryptedTimestamp = encTimestamp
                  , hiMac1 = mac1
                  , hiMac2 = mac2
                  }

-- | Parse a handshake response message (without the 4-byte header)
parseHandshakeResponse :: ByteString -> Either String HandshakeResponse
parseHandshakeResponse bs
  | BS.length bs /= 88 = Left $ "Invalid handshake response length: " ++ show (BS.length bs) ++ " (expected 88)"
  | otherwise =
      let senderIndex = getWord32LE bs 0
          receiverIndex = getWord32LE bs 4
          ephemeralBytes = BS.take 32 $ BS.drop 8 bs
          encNothing = BS.take 16 $ BS.drop 40 bs
          mac1 = BS.take 16 $ BS.drop 56 bs
          mac2 = BS.take 16 $ BS.drop 72 bs
       in case X25519.publicKey ephemeralBytes of
            CryptoFailed _ -> Left "Invalid ephemeral public key"
            CryptoPassed pk ->
              Right
                HandshakeResponse
                  { hrSenderIndex = senderIndex
                  , hrReceiverIndex = receiverIndex
                  , hrEphemeral = PublicKey pk
                  , hrEncryptedNothing = encNothing
                  , hrMac1 = mac1
                  , hrMac2 = mac2
                  }

-- | Parse a transport data message (without the 4-byte header)
parseTransportData :: ByteString -> Either String TransportData
parseTransportData bs
  | BS.length bs < 12 = Left "Transport message too short"
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
    , publicKeyToBytes hiEphemeral
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
    , publicKeyToBytes hrEphemeral
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
-- MAC Computation
--------------------------------------------------------------------------------

-- | Compute MAC1 for a handshake message
-- MAC1 = BLAKE2s(HASH(HASH("Noise_IKpsk2...") || "mac1----" || responder_public_key), msg)
computeMac1 ::
  -- | Responder's public key
  PublicKey ->
  -- | Message bytes (without MAC1 and MAC2)
  ByteString ->
  ByteString
computeMac1 responderPubKey msgWithoutMacs =
  let label = hashToBytes constructionHash <> mac1Label <> publicKeyToBytes responderPubKey
      key = hashToBytes $ hash label
   in BS.take 16 $ hashToBytes $ mac key msgWithoutMacs

-- | Compute MAC2 for a handshake message (when under load)
-- MAC2 = BLAKE2s(cookie, msg || mac1)
computeMac2 ::
  -- | Cookie
  ByteString ->
  -- | Message bytes (including MAC1, without MAC2)
  ByteString ->
  ByteString
computeMac2 cookie msgWithMac1 =
  BS.take 16 $ hashToBytes $ mac cookie msgWithMac1

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
