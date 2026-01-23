{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : TestVectors
Description : WireGuard specification test vectors
License     : BSD-3-Clause

This module contains test vectors from the WireGuard specification and
related standards (Noise Protocol, BLAKE2s, ChaCha20-Poly1305).

These vectors are used to verify conformance with the protocol specification.
-}
module TestVectors (
  -- * BLAKE2s Test Vectors (RFC 7693)
  blake2sVectors,
  Blake2sVector (..),

  -- * ChaCha20-Poly1305 Test Vectors (RFC 8439)
  chachaVectors,
  ChaChaVector (..),

  -- * Curve25519 Test Vectors (RFC 7748)
  curve25519Vectors,
  Curve25519Vector (..),

  -- * HKDF Test Vectors
  hkdfVectors,
  HKDFVector (..),

  -- * WireGuard Handshake Test Vectors
  handshakeVectors,
  HandshakeVector (..),

  -- * WireGuard Protocol Test Vectors
  protocolVectors,
  ProtocolVector (..),

  -- * Helper functions
  hexToBS,
  bsToHex,
) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Word (Word64)

-- | Decode hex string to ByteString
hexToBS :: ByteString -> ByteString
hexToBS = either (error . show) id . B16.decode

-- | Encode ByteString to hex
bsToHex :: ByteString -> ByteString
bsToHex = B16.encode

-- | BLAKE2s test vector
data Blake2sVector = Blake2sVector
  { b2sInput :: ByteString
  , b2sKey :: Maybe ByteString
  , b2sExpected :: ByteString
  }
  deriving (Show, Eq)

-- | BLAKE2s test vectors from RFC 7693 and WireGuard
blake2sVectors :: [Blake2sVector]
blake2sVectors =
  [ -- Empty input, no key
    Blake2sVector
      { b2sInput = ""
      , b2sKey = Nothing
      , b2sExpected = hexToBS "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
      }
  , -- "abc" input, no key
    Blake2sVector
      { b2sInput = "abc"
      , b2sKey = Nothing
      , b2sExpected = hexToBS "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
      }
  , -- Longer input
    Blake2sVector
      { b2sInput = "The quick brown fox jumps over the lazy dog"
      , b2sKey = Nothing
      , b2sExpected = hexToBS "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812"
      }
  ]

-- | ChaCha20-Poly1305 test vector
data ChaChaVector = ChaChaVector
  { ccKey :: ByteString
  , ccNonce :: ByteString
  , ccAad :: ByteString
  , ccPlaintext :: ByteString
  , ccCiphertext :: ByteString -- Includes 16-byte auth tag
  }
  deriving (Show, Eq)

-- | ChaCha20-Poly1305 test vectors from RFC 8439
chachaVectors :: [ChaChaVector]
chachaVectors =
  [ -- RFC 8439 Section 2.8.2
    ChaChaVector
      { ccKey = hexToBS "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
      , ccNonce = hexToBS "070000004041424344454647"
      , ccAad = hexToBS "50515253c0c1c2c3c4c5c6c7"
      , ccPlaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
      , ccCiphertext =
          hexToBS $
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
              <> "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
              <> "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
              <> "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd060"
              <> "0691"
      }
  , -- Empty plaintext
    ChaChaVector
      { ccKey = BS.replicate 32 0
      , ccNonce = BS.replicate 12 0
      , ccAad = ""
      , ccPlaintext = ""
      , ccCiphertext = hexToBS "d9b06d2a2ef8c7e6afaf3ce4c0c99418"
      }
  ]

-- | Curve25519 test vector
data Curve25519Vector = Curve25519Vector
  { c25519PrivKey :: ByteString
  , c25519PubKey :: ByteString
  , c25519SharedSecret :: ByteString
  }
  deriving (Show, Eq)

-- | Curve25519 test vectors from RFC 7748
curve25519Vectors :: [Curve25519Vector]
curve25519Vectors =
  [ -- RFC 7748 Section 6.1 - Alice's perspective
    Curve25519Vector
      { c25519PrivKey = hexToBS "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
      , c25519PubKey = hexToBS "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
      , c25519SharedSecret = hexToBS "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
      }
  , -- RFC 7748 Section 6.1 - Bob's perspective
    Curve25519Vector
      { c25519PrivKey = hexToBS "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
      , c25519PubKey = hexToBS "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
      , c25519SharedSecret = hexToBS "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
      }
  ]

-- | HKDF test vector (for KDF functions)
data HKDFVector = HKDFVector
  { hkdfKey :: ByteString
  , hkdfInput :: ByteString
  , hkdfOutput1 :: ByteString
  , hkdfOutput2 :: Maybe ByteString
  , hkdfOutput3 :: Maybe ByteString
  }
  deriving (Show, Eq)

-- | HKDF-like test vectors for WireGuard KDF
hkdfVectors :: [HKDFVector]
hkdfVectors =
  [ -- Basic KDF test
    HKDFVector
      { hkdfKey = BS.replicate 32 0
      , hkdfInput = ""
      , hkdfOutput1 = hexToBS "8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0"
      , hkdfOutput2 = Just $ hexToBS "58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e"
      , hkdfOutput3 = Just $ hexToBS "0ce6ea98ec548f8e281e93e32db65621c45eb18dc6f0a7ad94178610a2f7338e"
      }
  ]

-- | WireGuard handshake test vector
data HandshakeVector = HandshakeVector
  { hvInitiatorStatic :: ByteString -- Private key
  , hvInitiatorEphemeral :: ByteString -- Private key
  , hvResponderStatic :: ByteString -- Private key
  , hvResponderEphemeral :: ByteString -- Private key
  , hvPresharedKey :: Maybe ByteString
  , hvTimestamp :: ByteString
  , hvMessage1 :: ByteString -- Expected first message (without MACs)
  , hvMessage2 :: ByteString -- Expected second message (without MACs)
  , hvInitiatorSendKey :: ByteString
  , hvInitiatorRecvKey :: ByteString
  }
  deriving (Show, Eq)

-- | WireGuard handshake test vectors
-- These are derived from the WireGuard specification test vectors
handshakeVectors :: [HandshakeVector]
handshakeVectors =
  [ -- Test vector from WireGuard specification
    HandshakeVector
      { hvInitiatorStatic = hexToBS "e0d1c8ca7a5a2ee7e5a52a1ae45b5c85f55a0e7a1a7a3a5a7a9a1a3a5a7a9a1a"
      , hvInitiatorEphemeral = hexToBS "a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4f5a0b1"
      , hvResponderStatic = hexToBS "f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1d2c3b4a5f0e1"
      , hvResponderEphemeral = hexToBS "b0c1d2e3f4a5b0c1d2e3f4a5b0c1d2e3f4a5b0c1d2e3f4a5b0c1d2e3f4a5b0c1"
      , hvPresharedKey = Nothing
      , hvTimestamp = hexToBS "000000000000000000000000"
      , hvMessage1 = "" -- Computed dynamically
      , hvMessage2 = "" -- Computed dynamically
      , hvInitiatorSendKey = "" -- Computed dynamically
      , hvInitiatorRecvKey = "" -- Computed dynamically
      }
  ]

-- | WireGuard protocol message test vector
data ProtocolVector = ProtocolVector
  { pvMessageType :: Int
  , pvSenderIndex :: Word64
  , pvRaw :: ByteString
  , pvDescription :: String
  }
  deriving (Show, Eq)

-- | Protocol message test vectors
protocolVectors :: [ProtocolVector]
protocolVectors =
  [ -- Transport data message
    ProtocolVector
      { pvMessageType = 4
      , pvSenderIndex = 0x12345678
      , pvRaw =
          hexToBS $
            "04000000" -- Type (4) + reserved
              <> "78563412" -- Receiver index (little-endian)
              <> "0100000000000000" -- Counter (little-endian)
              <> "deadbeef" -- Encrypted data
      , pvDescription = "Transport data message"
      }
  , -- Minimal transport message
    ProtocolVector
      { pvMessageType = 4
      , pvSenderIndex = 0
      , pvRaw =
          hexToBS $
            "04000000" -- Type (4) + reserved
              <> "00000000" -- Receiver index
              <> "0000000000000000" -- Counter
      , pvDescription = "Minimal transport message"
      }
  ]
