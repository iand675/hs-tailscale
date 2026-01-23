{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Tailscale.WireGuard.Crypto
-- Description : Cryptographic primitives for WireGuard
-- License     : BSD-3-Clause
--
-- This module provides the cryptographic primitives used by the WireGuard
-- protocol:
--
-- * Curve25519 for ECDH key exchange
-- * ChaCha20-Poly1305 for AEAD encryption
-- * BLAKE2s for hashing and key derivation
--
-- These are used in the Noise_IK handshake pattern.
module Tailscale.WireGuard.Crypto
  ( -- * Key Types
    PrivateKey (..)
  , PublicKey (..)
  , SharedSecret (..)
  , SymmetricKey (..)
  , Nonce (..)
  , PresharedKey (..)
  , Hash (..)

    -- * Key Generation
  , generatePrivateKey
  , derivePublicKey
  , generatePresharedKey

    -- * ECDH
  , ecdh

    -- * AEAD Encryption (ChaCha20-Poly1305)
  , encrypt
  , decrypt

    -- * Hashing (BLAKE2s)
  , hash
  , mac
  , kdf1
  , kdf2
  , kdf3

    -- * Constants
  , hashLen
  , keyLen
  , nonceLen
  , tagLen

    -- * Utilities
  , constantTimeEq
  , zeroKey
  , nonceFromCounter
  ) where

import Crypto.Cipher.ChaChaPoly1305 (nonce12)
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaChaPoly
import Crypto.Error (CryptoFailable(..), throwCryptoError)
import Crypto.Hash (hashWith, Blake2s_256(..))
import Crypto.MAC.HMAC (HMAC(..), hmac)
import qualified Crypto.PubKey.Curve25519 as X25519
import Crypto.Random (MonadRandom, getRandomBytes)
import Data.Bits ((.&.), shiftR)
import Data.ByteArray (ByteArrayAccess, convert)
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64)

-- | WireGuard private key (Curve25519 scalar)
newtype PrivateKey = PrivateKey { unPrivateKey :: X25519.SecretKey }
  deriving (Eq)

instance Show PrivateKey where
  show _ = "PrivateKey{..}"

-- | WireGuard public key (Curve25519 point)
newtype PublicKey = PublicKey { unPublicKey :: X25519.PublicKey }
  deriving (Eq)

instance Show PublicKey where
  show (PublicKey pk) = "PublicKey " ++ show (BA.convert pk :: ByteString)

instance ByteArrayAccess PublicKey where
  length (PublicKey pk) = BA.length pk
  withByteArray (PublicKey pk) = BA.withByteArray pk

-- | Shared secret from ECDH
newtype SharedSecret = SharedSecret { unSharedSecret :: X25519.DhSecret }
  deriving (Eq)

-- | Symmetric encryption key (32 bytes)
newtype SymmetricKey = SymmetricKey { unSymmetricKey :: ByteString }
  deriving (Eq, Show, ByteArrayAccess)

-- | Nonce for ChaCha20-Poly1305 (12 bytes, constructed from 64-bit counter)
newtype Nonce = Nonce { unNonce :: ByteString }
  deriving (Eq, Show, ByteArrayAccess)

-- | Preshared key (optional, 32 bytes)
newtype PresharedKey = PresharedKey { unPresharedKey :: ByteString }
  deriving (Eq, ByteArrayAccess)

instance Show PresharedKey where
  show _ = "PresharedKey{..}"

-- | Hash value (BLAKE2s-256, 32 bytes)
newtype Hash = Hash { unHash :: ByteString }
  deriving (Eq, Show, ByteArrayAccess)

-- | Length of hash output (32 bytes)
hashLen :: Int
hashLen = 32

-- | Length of symmetric keys (32 bytes)
keyLen :: Int
keyLen = 32

-- | Length of nonce (12 bytes for ChaCha20-Poly1305)
nonceLen :: Int
nonceLen = 12

-- | Length of authentication tag (16 bytes)
tagLen :: Int
tagLen = 16

-- | Generate a new random private key
generatePrivateKey :: MonadRandom m => m PrivateKey
generatePrivateKey = do
  bytes <- getRandomBytes 32
  case X25519.secretKey (bytes :: ByteString) of
    CryptoFailed _ -> generatePrivateKey  -- Retry on failure (very rare)
    CryptoPassed sk -> pure $ PrivateKey sk

-- | Derive the public key from a private key
derivePublicKey :: PrivateKey -> PublicKey
derivePublicKey (PrivateKey sk) = PublicKey $ X25519.toPublic sk

-- | Generate a random preshared key
generatePresharedKey :: MonadRandom m => m PresharedKey
generatePresharedKey = PresharedKey <$> getRandomBytes 32

-- | Perform ECDH key exchange
ecdh :: PrivateKey -> PublicKey -> SharedSecret
ecdh (PrivateKey sk) (PublicKey pk) = SharedSecret $ X25519.dh pk sk

-- | Encrypt with ChaCha20-Poly1305
--
-- Returns ciphertext || auth_tag (16 bytes)
encrypt :: SymmetricKey -> Nonce -> ByteString -> ByteString -> ByteString
encrypt (SymmetricKey key) (Nonce n) aad plaintext =
  let state0 = throwCryptoError $ ChaChaPoly.initialize key (throwCryptoError $ nonce12 n)
      state1 = ChaChaPoly.finalizeAAD $ ChaChaPoly.appendAAD aad state0
      (ciphertext, state2) = ChaChaPoly.encrypt plaintext state1
      authTag = ChaChaPoly.finalize state2
  in ciphertext <> convert authTag

-- | Decrypt with ChaCha20-Poly1305
--
-- Input is ciphertext || auth_tag. Returns Nothing on authentication failure.
decrypt :: SymmetricKey -> Nonce -> ByteString -> ByteString -> Maybe ByteString
decrypt (SymmetricKey key) (Nonce n) aad ciphertextWithTag
  | BS.length ciphertextWithTag < tagLen = Nothing
  | otherwise =
      let (ciphertext, tagBytes) = BS.splitAt (BS.length ciphertextWithTag - tagLen) ciphertextWithTag
          state0 = throwCryptoError $ ChaChaPoly.initialize key (throwCryptoError $ nonce12 n)
          state1 = ChaChaPoly.finalizeAAD $ ChaChaPoly.appendAAD aad state0
          (plaintext, state2) = ChaChaPoly.decrypt ciphertext state1
          computedTag = ChaChaPoly.finalize state2
      in if convert computedTag `constantTimeEq` tagBytes
           then Just plaintext
           else Nothing

-- | BLAKE2s-256 hash
hash :: ByteString -> Hash
hash input = Hash $ convert $ hashWith Blake2s_256 input

-- | BLAKE2s-256 keyed hash (HMAC-like MAC)
mac :: ByteString -> ByteString -> Hash
mac key input =
  let HMAC result = hmac key input :: HMAC Blake2s_256
  in Hash $ convert result

-- | Key derivation function (1 output)
--
-- @kdf1 key input = HMAC(HMAC(key, input), 0x01)@
kdf1 :: ByteString -> ByteString -> SymmetricKey
kdf1 key input =
  let HMAC t0 = hmac key input :: HMAC Blake2s_256
      HMAC t1 = hmac (convert t0) (BS.singleton 0x01) :: HMAC Blake2s_256
  in SymmetricKey $ convert t1

-- | Key derivation function (2 outputs)
--
-- Returns (k1, k2) where:
-- @t0 = HMAC(key, input)@
-- @k1 = HMAC(t0, 0x01)@
-- @k2 = HMAC(t0, k1 || 0x02)@
kdf2 :: ByteString -> ByteString -> (SymmetricKey, SymmetricKey)
kdf2 key input =
  let HMAC t0 = hmac key input :: HMAC Blake2s_256
      t0Bytes = convert t0
      HMAC t1 = hmac t0Bytes (BS.singleton 0x01) :: HMAC Blake2s_256
      t1Bytes = convert t1
      HMAC t2 = hmac t0Bytes (t1Bytes <> BS.singleton 0x02) :: HMAC Blake2s_256
  in (SymmetricKey t1Bytes, SymmetricKey $ convert t2)

-- | Key derivation function (3 outputs)
--
-- Returns (k1, k2, k3)
kdf3 :: ByteString -> ByteString -> (SymmetricKey, SymmetricKey, SymmetricKey)
kdf3 key input =
  let HMAC t0 = hmac key input :: HMAC Blake2s_256
      t0Bytes = convert t0
      HMAC t1 = hmac t0Bytes (BS.singleton 0x01) :: HMAC Blake2s_256
      t1Bytes = convert t1
      HMAC t2 = hmac t0Bytes (t1Bytes <> BS.singleton 0x02) :: HMAC Blake2s_256
      t2Bytes = convert t2
      HMAC t3 = hmac t0Bytes (t2Bytes <> BS.singleton 0x03) :: HMAC Blake2s_256
  in (SymmetricKey t1Bytes, SymmetricKey t2Bytes, SymmetricKey $ convert t3)

-- | Constant-time byte string comparison
constantTimeEq :: ByteString -> ByteString -> Bool
constantTimeEq = BA.constEq

-- | Create a nonce from a 64-bit counter
--
-- WireGuard uses an 8-byte counter with 4 bytes of zero padding
nonceFromCounter :: Word64 -> Nonce
nonceFromCounter counter =
  let bytes = BS.pack
        [ 0, 0, 0, 0  -- 4 bytes padding
        , fromIntegral (counter .&. 0xFF)
        , fromIntegral ((counter `shiftR` 8) .&. 0xFF)
        , fromIntegral ((counter `shiftR` 16) .&. 0xFF)
        , fromIntegral ((counter `shiftR` 24) .&. 0xFF)
        , fromIntegral ((counter `shiftR` 32) .&. 0xFF)
        , fromIntegral ((counter `shiftR` 40) .&. 0xFF)
        , fromIntegral ((counter `shiftR` 48) .&. 0xFF)
        , fromIntegral ((counter `shiftR` 56) .&. 0xFF)
        ]
  in Nonce bytes
  where
    (.&.) = (Data.Bits..&.)
    shiftR = Data.Bits.shiftR

-- | All-zero symmetric key
zeroKey :: SymmetricKey
zeroKey = SymmetricKey $ BS.replicate 32 0
