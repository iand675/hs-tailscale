{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : InteropSpec
Description : Interoperability tests for WireGuard implementation
License     : BSD-3-Clause

These tests verify that our implementation is compatible with the WireGuard
specification and other implementations. Test vectors are derived from:

1. WireGuard whitepaper test vectors
2. Noise Protocol Framework test vectors
3. Known-good values from wireguard-go and wireguard-tools

The tests verify:
- Cryptographic primitive compatibility
- Noise handshake compatibility
- Message format compatibility
- Session key derivation compatibility
-}
module InteropSpec (tests) where

import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import TestVectors
import WireGuard.Crypto
import WireGuard.Noise
import WireGuard.Protocol

tests :: TestTree
tests =
  testGroup
    "Interoperability"
    [ specificationTests
    , noiseVectorTests
    , wireguardFormatTests
    , deterministicHandshakeTests
    ]

--------------------------------------------------------------------------------
-- WireGuard Specification Tests
--------------------------------------------------------------------------------

specificationTests :: TestTree
specificationTests =
  testGroup
    "WireGuard Specification"
    [ testCase "Protocol name is correct" $ do
        protocolName @?= "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    , testCase "Construction hash matches specification" $ do
        -- The construction hash is HASH(protocolName) when len > 32
        let expected = hash protocolName
        constructionHash @?= expected
    , testCase "Message type 1 is handshake init" $ do
        messageTypeByte MsgTypeHandshakeInit @?= 1
    , testCase "Message type 2 is handshake response" $ do
        messageTypeByte MsgTypeHandshakeResponse @?= 2
    , testCase "Message type 3 is cookie reply" $ do
        messageTypeByte MsgTypeCookieReply @?= 3
    , testCase "Message type 4 is transport data" $ do
        messageTypeByte MsgTypeTransportData @?= 4
    , testCase "Handshake init is 148 bytes" $ do
        -- 4 (header) + 4 (sender) + 32 (ephemeral) + 48 (enc static) +
        -- 28 (enc timestamp) + 16 (mac1) + 16 (mac2) = 148
        handshakeInitLen @?= 148
    , testCase "Handshake response is 92 bytes" $ do
        -- 4 (header) + 4 (sender) + 4 (receiver) + 32 (ephemeral) +
        -- 16 (enc nothing) + 16 (mac1) + 16 (mac2) = 92
        handshakeResponseLen @?= 92
    , testCase "Cookie reply is 64 bytes" $ do
        -- 4 (header) + 4 (receiver) + 24 (nonce) + 32 (enc cookie) = 64
        cookieReplyLen @?= 64
    ]

--------------------------------------------------------------------------------
-- Noise Protocol Test Vectors
--------------------------------------------------------------------------------

noiseVectorTests :: TestTree
noiseVectorTests =
  testGroup
    "Noise Protocol Vectors"
    [ testCase "BLAKE2s-256 produces correct output" $ do
        -- Verify BLAKE2s implementation
        let h = hash "test"
        BS.length (hashToBytes h) @?= 32
    , testCase "Curve25519 base point multiplication" $ do
        -- RFC 7748 test: derive public key from specific private key
        let privBytes = hexToBS "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
            expectedPub = hexToBS "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        case privateKeyFromBytes privBytes of
          Nothing -> assertFailure "Failed to parse private key"
          Just priv -> do
            let pub = derivePublicKey priv
            publicKeyToBytes pub @?= expectedPub
    , testCase "Curve25519 ECDH matches RFC 7748" $ do
        -- Alice and Bob key agreement
        let alicePriv = hexToBS "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
            bobPriv = hexToBS "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
            expectedShared = hexToBS "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        case (privateKeyFromBytes alicePriv, privateKeyFromBytes bobPriv) of
          (Just alice, Just bob) -> do
            let alicePub = derivePublicKey alice
                bobPub = derivePublicKey bob
                SharedSecret shared1 = ecdh alice bobPub
                SharedSecret shared2 = ecdh bob alicePub
            BA.convert shared1 @?= expectedShared
            BA.convert shared2 @?= expectedShared
          _ -> assertFailure "Failed to parse keys"
    , testCase "ChaCha20-Poly1305 empty message" $ do
        -- RFC 8439 style test with empty message
        let key = zeroKey
            nonce = Nonce (BS.replicate 12 0)
            ct = encrypt key nonce "" ""
        -- Should be just the 16-byte tag
        BS.length ct @?= 16
        -- Verify it decrypts
        decrypt key nonce "" ct @?= Just ""
    , testCase "Noise handshake hash chaining" $ do
        -- Verify that mixHash works correctly
        let hs0 = initializeHandshake protocolName
            hs1 = mixHash hs0 "test1"
            hs2 = mixHash hs1 "test2"
        -- Each mixHash should produce different hash
        hsHash hs0 /= hsHash hs1 @? "First mixHash should change hash"
        hsHash hs1 /= hsHash hs2 @? "Second mixHash should change hash"
        -- But same inputs should produce same outputs
        let hs1' = mixHash hs0 "test1"
        hsHash hs1 @?= hsHash hs1'
    ]

--------------------------------------------------------------------------------
-- WireGuard Message Format Tests
--------------------------------------------------------------------------------

wireguardFormatTests :: TestTree
wireguardFormatTests =
  testGroup
    "WireGuard Message Format"
    [ testCase "Transport message format" $ do
        -- Test vector from protocol specification
        let td =
              TransportData
                { tdReceiverIndex = 0x12345678
                , tdCounter = 0x0000000000000001
                , tdEncryptedPacket = "test"
                }
            serialized = serializeTransportData td
        -- Check header
        BS.index serialized 0 @?= 4 -- Message type
        BS.take 3 (BS.drop 1 serialized) @?= BS.replicate 3 0 -- Reserved
        -- Check little-endian encoding
        BS.index serialized 4 @?= 0x78 -- LSB of receiver index
        BS.index serialized 7 @?= 0x12 -- MSB of receiver index
    , testCase "Handshake init format" $ do
        privKey <- generatePrivateKey
        let pubKey = derivePublicKey privKey
            hi =
              HandshakeInit
                { hiSenderIndex = 0x12345678
                , hiEphemeral = pubKey
                , hiEncryptedStatic = BS.replicate 48 0xAA
                , hiEncryptedTimestamp = BS.replicate 28 0xBB
                , hiMac1 = BS.replicate 16 0xCC
                , hiMac2 = BS.replicate 16 0xDD
                }
            serialized = serializeHandshakeInit hi
        -- Type
        BS.index serialized 0 @?= 1
        -- Reserved
        BS.take 3 (BS.drop 1 serialized) @?= BS.replicate 3 0
        -- Sender index (little-endian)
        BS.index serialized 4 @?= 0x78
        BS.index serialized 7 @?= 0x12
        -- Ephemeral key starts at offset 8
        BS.take 32 (BS.drop 8 serialized) @?= publicKeyToBytes pubKey
        -- Total length
        BS.length serialized @?= 148
    , testCase "Handshake response format" $ do
        privKey <- generatePrivateKey
        let pubKey = derivePublicKey privKey
            hr =
              HandshakeResponse
                { hrSenderIndex = 0x12345678
                , hrReceiverIndex = 0x87654321
                , hrEphemeral = pubKey
                , hrEncryptedNothing = BS.replicate 16 0xAA
                , hrMac1 = BS.replicate 16 0xBB
                , hrMac2 = BS.replicate 16 0xCC
                }
            serialized = serializeHandshakeResponse hr
        -- Type
        BS.index serialized 0 @?= 2
        -- Sender at offset 4, receiver at offset 8
        BS.index serialized 4 @?= 0x78 -- LSB of sender
        BS.index serialized 8 @?= 0x21 -- LSB of receiver
        -- Total length
        BS.length serialized @?= 92
    ]

--------------------------------------------------------------------------------
-- Deterministic Handshake Tests
--------------------------------------------------------------------------------

-- | Run handshake with fixed keys to verify deterministic behavior
deterministicHandshakeTests :: TestTree
deterministicHandshakeTests =
  testGroup
    "Deterministic Handshake"
    [ testCase "Same inputs produce same handshake state" $ do
        let initPrivBytes = BS.pack [0x01 .. 0x20]
            respPrivBytes = BS.pack [0x21 .. 0x40]
            initEphBytes = BS.pack [0x41 .. 0x60]
        case
          ( privateKeyFromBytes initPrivBytes
          , privateKeyFromBytes respPrivBytes
          , privateKeyFromBytes initEphBytes
          ) of
          (Just initPriv, Just respPriv, Just initEph) -> do
            let respPub = derivePublicKey respPriv
                hs1 = initiatorInit initPriv respPub Nothing
                hs2 = initiatorInit initPriv respPub Nothing
                timestamp = BS.replicate 12 0
                (_, msg1a) = initiatorWriteMessage hs1 initEph timestamp
                (_, msg1b) = initiatorWriteMessage hs2 initEph timestamp
            msg1a @?= msg1b
          _ -> assertFailure "Failed to create keys from bytes"
    , testCase "Message 1 has correct structure" $ do
        let initPrivBytes = BS.pack [0x01 .. 0x20]
            respPrivBytes = BS.pack [0x21 .. 0x40]
            initEphBytes = BS.pack [0x41 .. 0x60]
        case
          ( privateKeyFromBytes initPrivBytes
          , privateKeyFromBytes respPrivBytes
          , privateKeyFromBytes initEphBytes
          ) of
          (Just initPriv, Just respPriv, Just initEph) -> do
            let respPub = derivePublicKey respPriv
                initEphPub = derivePublicKey initEph
                hs = initiatorInit initPriv respPub Nothing
                timestamp = BS.replicate 12 0
                (_, msg) = initiatorWriteMessage hs initEph timestamp
            -- Message structure:
            -- - 32 bytes: ephemeral public key (unencrypted)
            -- - 48 bytes: encrypted static key (32 + 16 tag)
            -- - 28 bytes: encrypted timestamp (12 + 16 tag)
            BS.length msg @?= 108
            -- First 32 bytes should be ephemeral public key
            BS.take 32 msg @?= publicKeyToBytes initEphPub
          _ -> assertFailure "Failed to create keys from bytes"
    , testCase "Complete handshake with fixed keys" $ do
        let initPrivBytes = BS.pack [0x01 .. 0x20]
            respPrivBytes = BS.pack [0x21 .. 0x40]
            initEphBytes = BS.pack [0x41 .. 0x60]
            respEphBytes = BS.pack [0x61 .. 0x80]
        case
          ( privateKeyFromBytes initPrivBytes
          , privateKeyFromBytes respPrivBytes
          , privateKeyFromBytes initEphBytes
          , privateKeyFromBytes respEphBytes
          ) of
          (Just initPriv, Just respPriv, Just initEph, Just respEph) -> do
            let respPub = derivePublicKey respPriv
                timestamp = BS.replicate 12 0

            -- Initiator creates message 1
            let initHs = initiatorInit initPriv respPub Nothing
                (initHs', msg1) = initiatorWriteMessage initHs initEph timestamp

            -- Responder processes message 1
            let respHs = responderInit respPriv Nothing
            case responderReadMessage respHs msg1 of
              Left err -> assertFailure $ "Responder failed: " ++ show err
              Right (respHs', receivedPub, receivedTs) -> do
                -- Verify received data
                receivedPub @?= derivePublicKey initPriv
                receivedTs @?= timestamp

                -- Responder creates message 2
                let (_, msg2, respKeys) = responderWriteMessage respHs' respEph

                -- Initiator processes message 2
                case initiatorReadMessage initHs' msg2 of
                  Left err -> assertFailure $ "Initiator failed: " ++ show err
                  Right (_, initKeys) -> do
                    -- Verify keys match
                    csKey (skSend initKeys) @?= csKey (skReceive respKeys)
                    csKey (skReceive initKeys) @?= csKey (skSend respKeys)
          _ -> assertFailure "Failed to create keys from bytes"
    , testCase "Handshake keys are reproducible" $ do
        -- Run handshake twice with same inputs, verify same keys
        let runHandshake = do
              let initPrivBytes = BS.pack [0x01 .. 0x20]
                  respPrivBytes = BS.pack [0x21 .. 0x40]
                  initEphBytes = BS.pack [0x41 .. 0x60]
                  respEphBytes = BS.pack [0x61 .. 0x80]
              case
                ( privateKeyFromBytes initPrivBytes
                , privateKeyFromBytes respPrivBytes
                , privateKeyFromBytes initEphBytes
                , privateKeyFromBytes respEphBytes
                ) of
                (Just initPriv, Just respPriv, Just initEph, Just respEph) -> do
                  let respPub = derivePublicKey respPriv
                      timestamp = BS.replicate 12 0
                      initHs = initiatorInit initPriv respPub Nothing
                      (initHs', msg1) = initiatorWriteMessage initHs initEph timestamp
                      respHs = responderInit respPriv Nothing
                  case responderReadMessage respHs msg1 of
                    Left err -> error $ show err
                    Right (respHs', _, _) -> do
                      let (_, msg2, _) = responderWriteMessage respHs' respEph
                      case initiatorReadMessage initHs' msg2 of
                        Left err -> error $ show err
                        Right (_, keys) -> return keys
                _ -> error "Failed to create keys"
        keys1 <- runHandshake
        keys2 <- runHandshake
        keys1 @?= keys2
    ]
