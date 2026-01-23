{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE BangPatterns #-}

-- |
-- Module      : Tailscale.WireGuard.Noise
-- Description : Noise_IK handshake implementation for WireGuard
-- License     : BSD-3-Clause
--
-- This module implements the Noise_IK handshake pattern used by WireGuard.
-- The handshake provides mutual authentication and establishes symmetric
-- keys for data encryption.
--
-- Noise_IK pattern:
--
-- @
-- <- s
-- ...
-- -> e, es, s, ss
-- <- e, ee, se
-- @
--
-- Where:
--
-- * @s@ = static key pair
-- * @e@ = ephemeral key pair
-- * @es@ = DH(initiator_ephemeral, responder_static)
-- * @ss@ = DH(initiator_static, responder_static)
-- * @ee@ = DH(initiator_ephemeral, responder_ephemeral)
-- * @se@ = DH(initiator_static, responder_ephemeral)
module Tailscale.WireGuard.Noise
  ( -- * Handshake State
    HandshakeState (..)
  , NoiseError (..)
  , CipherState (..)

    -- * Initiator (Client)
  , initiatorInit
  , initiatorWriteMessage
  , initiatorReadMessage

    -- * Responder (Server)
  , responderInit
  , responderReadMessage
  , responderWriteMessage

    -- * Constants
  , protocolName
  , prologue

    -- * Session Keys
  , SessionKeys (..)
  , deriveSessionKeys
  ) where

import Crypto.Error (CryptoFailable(..))
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64)

import Tailscale.WireGuard.Crypto

-- | WireGuard protocol name for Noise
protocolName :: ByteString
protocolName = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

-- | WireGuard prologue (empty)
prologue :: ByteString
prologue = ""

-- | Errors that can occur during handshake
data NoiseError
  = DecryptionFailed
  | InvalidMessageLength
  | InvalidPublicKey
  | HandshakeNotComplete
  deriving (Eq, Show)

-- | State for symmetric encryption after handshake
data CipherState = CipherState
  { csKey     :: !SymmetricKey
  , csNonce   :: !Word64
  }
  deriving (Eq, Show)

-- | Increment the nonce in a cipher state
incrementNonce :: CipherState -> CipherState
incrementNonce cs = cs { csNonce = csNonce cs + 1 }

-- | Session keys derived from completed handshake
data SessionKeys = SessionKeys
  { skSend    :: !CipherState  -- ^ Key for sending
  , skReceive :: !CipherState  -- ^ Key for receiving
  }
  deriving (Eq, Show)

-- | Handshake state
data HandshakeState = HandshakeState
  { hsLocalStatic      :: !PrivateKey
  , hsLocalEphemeral   :: !(Maybe PrivateKey)
  , hsRemoteStatic     :: !(Maybe PublicKey)
  , hsRemoteEphemeral  :: !(Maybe PublicKey)
  , hsPresharedKey     :: !(Maybe PresharedKey)
  , hsChainingKey      :: !ByteString
  , hsHash             :: !ByteString
  , hsSymmetricKey     :: !SymmetricKey
  }
  deriving (Show)

-- | Initialize handshake state with protocol name
initializeHandshake :: ByteString -> HandshakeState
initializeHandshake protoName =
  let h = if BS.length protoName <= hashLen
            then protoName <> BS.replicate (hashLen - BS.length protoName) 0
            else unHash $ hash protoName
      ck = h
  in HandshakeState
       { hsLocalStatic = error "local static not set"
       , hsLocalEphemeral = Nothing
       , hsRemoteStatic = Nothing
       , hsRemoteEphemeral = Nothing
       , hsPresharedKey = Nothing
       , hsChainingKey = ck
       , hsHash = h
       , hsSymmetricKey = zeroKey
       }

-- | Mix a value into the hash
mixHash :: HandshakeState -> ByteString -> HandshakeState
mixHash hs input =
  let Hash newHash = hash (hsHash hs <> input)
  in hs { hsHash = newHash }

-- | Mix a DH result into the chaining key and symmetric key
mixKey :: HandshakeState -> ByteString -> HandshakeState
mixKey hs dhResult =
  let (ck, k) = kdf2 (hsChainingKey hs) dhResult
  in hs { hsChainingKey = unSymmetricKey ck, hsSymmetricKey = k }

-- | Mix the preshared key
mixKeyAndHash :: HandshakeState -> ByteString -> HandshakeState
mixKeyAndHash hs psk =
  let (ck, temp, k) = kdf3 (hsChainingKey hs) psk
      Hash newHash = hash (hsHash hs <> unSymmetricKey temp)
  in hs { hsChainingKey = unSymmetricKey ck, hsHash = newHash, hsSymmetricKey = k }

-- | Encrypt and authenticate data with associated data being the hash
encryptAndHash :: HandshakeState -> ByteString -> (HandshakeState, ByteString)
encryptAndHash hs plaintext =
  let ciphertext = encrypt (hsSymmetricKey hs) (Nonce $ BS.replicate 12 0) (hsHash hs) plaintext
      hs' = mixHash hs ciphertext
  in (hs', ciphertext)

-- | Decrypt and authenticate data
decryptAndHash :: HandshakeState -> ByteString -> Either NoiseError (HandshakeState, ByteString)
decryptAndHash hs ciphertext =
  case decrypt (hsSymmetricKey hs) (Nonce $ BS.replicate 12 0) (hsHash hs) ciphertext of
    Nothing -> Left DecryptionFailed
    Just plaintext ->
      let hs' = mixHash hs ciphertext
      in Right (hs', plaintext)

--------------------------------------------------------------------------------
-- Initiator (Client)
--------------------------------------------------------------------------------

-- | Initialize the initiator's handshake state
--
-- The initiator knows the responder's static public key beforehand.
initiatorInit
  :: PrivateKey      -- ^ Initiator's static private key
  -> PublicKey       -- ^ Responder's static public key
  -> Maybe PresharedKey  -- ^ Optional preshared key
  -> HandshakeState
initiatorInit localStatic remoteStatic psk =
  let hs0 = initializeHandshake protocolName
      hs1 = mixHash hs0 prologue
      -- Mix in responder's static public key (known ahead of time)
      hs2 = mixHash hs1 (BA.convert remoteStatic)
  in hs2
       { hsLocalStatic = localStatic
       , hsRemoteStatic = Just remoteStatic
       , hsPresharedKey = psk
       }

-- | Initiator creates the first handshake message
--
-- Message format: ephemeral_pub (32) || encrypted_static_pub (48) || encrypted_timestamp (28)
initiatorWriteMessage
  :: HandshakeState
  -> PrivateKey       -- ^ Fresh ephemeral key
  -> ByteString       -- ^ Timestamp (12 bytes typically)
  -> (HandshakeState, ByteString)
initiatorWriteMessage hs0 ephemeral timestamp =
  let ephemeralPub = derivePublicKey ephemeral
      hs1 = hs0 { hsLocalEphemeral = Just ephemeral }

      -- e: Send ephemeral public key
      hs2 = mixHash hs1 (BA.convert ephemeralPub)

      -- es: DH(ephemeral, remote_static)
      Just remoteStatic = hsRemoteStatic hs2
      SharedSecret dhEs = ecdh ephemeral remoteStatic
      hs3 = mixKey hs2 (BA.convert dhEs)

      -- s: Encrypt and send static public key
      localStaticPub = derivePublicKey (hsLocalStatic hs3)
      (hs4, encryptedStatic) = encryptAndHash hs3 (BA.convert localStaticPub)

      -- ss: DH(local_static, remote_static)
      SharedSecret dhSs = ecdh (hsLocalStatic hs4) remoteStatic
      hs5 = mixKey hs4 (BA.convert dhSs)

      -- Encrypt timestamp
      (hs6, encryptedTimestamp) = encryptAndHash hs5 timestamp

      -- Construct message
      message = BA.convert ephemeralPub <> encryptedStatic <> encryptedTimestamp

  in (hs6, message)

-- | Initiator reads the second handshake message
--
-- Message format: ephemeral_pub (32) || encrypted_nothing (16)
initiatorReadMessage
  :: HandshakeState
  -> ByteString
  -> Either NoiseError (HandshakeState, SessionKeys)
initiatorReadMessage hs0 message
  | BS.length message < 32 + 16 = Left InvalidMessageLength
  | otherwise =
      let (ephemeralBytes, rest) = BS.splitAt 32 message

          -- e: Receive ephemeral public key
          remoteEphemeral = PublicKey $ throwCryptoError $
            X25519.publicKey ephemeralBytes
          hs1 = mixHash hs0 ephemeralBytes
          hs2 = hs1 { hsRemoteEphemeral = Just remoteEphemeral }

          -- ee: DH(local_ephemeral, remote_ephemeral)
          Just localEphemeral = hsLocalEphemeral hs2
          SharedSecret dhEe = ecdh localEphemeral remoteEphemeral
          hs3 = mixKey hs2 (BA.convert dhEe)

          -- se: DH(local_static, remote_ephemeral)
          SharedSecret dhSe = ecdh (hsLocalStatic hs3) remoteEphemeral
          hs4 = mixKey hs3 (BA.convert dhSe)

          -- psk: Mix in preshared key if present
          hs5 = case hsPresharedKey hs4 of
            Nothing -> hs4
            Just (PresharedKey psk) -> mixKeyAndHash hs4 psk

      in do
        -- Decrypt (empty payload)
        (hs6, _) <- decryptAndHash hs5 rest

        -- Derive session keys
        let keys = deriveSessionKeys hs6

        Right (hs6, keys)
  where
    throwCryptoError (CryptoFailed _) = error "invalid public key"
    throwCryptoError (CryptoPassed x) = x

--------------------------------------------------------------------------------
-- Responder (Server)
--------------------------------------------------------------------------------

-- | Initialize the responder's handshake state
responderInit
  :: PrivateKey      -- ^ Responder's static private key
  -> Maybe PresharedKey  -- ^ Optional preshared key
  -> HandshakeState
responderInit localStatic psk =
  let hs0 = initializeHandshake protocolName
      hs1 = mixHash hs0 prologue
      -- Mix in our static public key
      localStaticPub = derivePublicKey localStatic
      hs2 = mixHash hs1 (BA.convert localStaticPub)
  in hs2
       { hsLocalStatic = localStatic
       , hsPresharedKey = psk
       }

-- | Responder reads the first handshake message
responderReadMessage
  :: HandshakeState
  -> ByteString
  -> Either NoiseError (HandshakeState, PublicKey, ByteString)
responderReadMessage hs0 message
  | BS.length message < 32 + 48 + 28 = Left InvalidMessageLength
  | otherwise =
      let (ephemeralBytes, rest1) = BS.splitAt 32 message
          (encryptedStatic, encryptedTimestamp) = BS.splitAt 48 rest1

          -- e: Receive ephemeral public key
          remoteEphemeral = PublicKey $ throwCryptoError $
            X25519.publicKey ephemeralBytes
          hs1 = mixHash hs0 ephemeralBytes
          hs2 = hs1 { hsRemoteEphemeral = Just remoteEphemeral }

          -- es: DH(local_static, remote_ephemeral)
          SharedSecret dhEs = ecdh (hsLocalStatic hs2) remoteEphemeral
          hs3 = mixKey hs2 (BA.convert dhEs)

      in do
        -- s: Decrypt static public key
        (hs4, staticBytes) <- decryptAndHash hs3 encryptedStatic
        let remoteStatic = PublicKey $ throwCryptoError $
              X25519.publicKey staticBytes
            hs5 = hs4 { hsRemoteStatic = Just remoteStatic }

        -- ss: DH(local_static, remote_static)
        let SharedSecret dhSs = ecdh (hsLocalStatic hs5) remoteStatic
            hs6 = mixKey hs5 (BA.convert dhSs)

        -- Decrypt timestamp
        (hs7, timestamp) <- decryptAndHash hs6 encryptedTimestamp

        Right (hs7, remoteStatic, timestamp)
  where
    throwCryptoError (CryptoFailed _) = error "invalid public key"
    throwCryptoError (CryptoPassed x) = x

-- | Responder creates the second handshake message
responderWriteMessage
  :: HandshakeState
  -> PrivateKey       -- ^ Fresh ephemeral key
  -> (HandshakeState, ByteString, SessionKeys)
responderWriteMessage hs0 ephemeral =
  let ephemeralPub = derivePublicKey ephemeral
      hs1 = hs0 { hsLocalEphemeral = Just ephemeral }

      -- e: Send ephemeral public key
      hs2 = mixHash hs1 (BA.convert ephemeralPub)

      -- ee: DH(local_ephemeral, remote_ephemeral)
      Just remoteEphemeral = hsRemoteEphemeral hs2
      SharedSecret dhEe = ecdh ephemeral remoteEphemeral
      hs3 = mixKey hs2 (BA.convert dhEe)

      -- se: DH(local_ephemeral, remote_static)
      Just remoteStatic = hsRemoteStatic hs3
      SharedSecret dhSe = ecdh ephemeral remoteStatic
      hs4 = mixKey hs3 (BA.convert dhSe)

      -- psk: Mix in preshared key if present
      hs5 = case hsPresharedKey hs4 of
        Nothing -> hs4
        Just (PresharedKey psk) -> mixKeyAndHash hs4 psk

      -- Encrypt empty payload
      (hs6, encrypted) = encryptAndHash hs5 ""

      -- Construct message
      message = BA.convert ephemeralPub <> encrypted

      -- Derive session keys (swapped for responder)
      keys = deriveSessionKeysResponder hs6

  in (hs6, message, keys)

--------------------------------------------------------------------------------
-- Session Key Derivation
--------------------------------------------------------------------------------

-- | Derive session keys after handshake completion (initiator)
deriveSessionKeys :: HandshakeState -> SessionKeys
deriveSessionKeys hs =
  let (k1, k2) = kdf2 (hsChainingKey hs) ""
  in SessionKeys
       { skSend = CipherState { csKey = k1, csNonce = 0 }
       , skReceive = CipherState { csKey = k2, csNonce = 0 }
       }

-- | Derive session keys after handshake completion (responder)
-- Note: Send/receive are swapped compared to initiator
deriveSessionKeysResponder :: HandshakeState -> SessionKeys
deriveSessionKeysResponder hs =
  let (k1, k2) = kdf2 (hsChainingKey hs) ""
  in SessionKeys
       { skSend = CipherState { csKey = k2, csNonce = 0 }
       , skReceive = CipherState { csKey = k1, csNonce = 0 }
       }
