{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : ProtocolSpec
Description : Tests for WireGuard protocol message handling
License     : BSD-3-Clause
-}
module ProtocolSpec (tests) where

import qualified Data.ByteString as BS
import Data.Word (Word32, Word64)
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import TestVectors
import WireGuard.Bits
import WireGuard.Crypto
import WireGuard.Noise (SessionKeys (..), CipherState (..))
import WireGuard.Protocol

tests :: TestTree
tests =
  testGroup
    "Protocol"
    [ constantsTests
    , messageTypeTests
    , parsingTests
    , serializationTests
    , roundtripTests
    , transportTests
    , macTests
    , bitsTests
    , propertyTests
    ]

--------------------------------------------------------------------------------
-- Constants Tests
--------------------------------------------------------------------------------

constantsTests :: TestTree
constantsTests =
  testGroup
    "Constants"
    [ testCase "rekeyAfterMessages is correct" $ do
        rekeyAfterMessages @?= 2 ^ (60 :: Int) - 1
    , testCase "rejectAfterMessages is correct" $ do
        rejectAfterMessages @?= 2 ^ (64 :: Int) - 2 ^ (4 :: Int) - 1
    , testCase "handshakeInitLen is 148" $ do
        handshakeInitLen @?= 148
    , testCase "handshakeResponseLen is 92" $ do
        handshakeResponseLen @?= 92
    , testCase "cookieReplyLen is 64" $ do
        cookieReplyLen @?= 64
    , testCase "transportHeaderLen is 16" $ do
        transportHeaderLen @?= 16
    , testCase "mac1Label is correct" $ do
        mac1Label @?= "mac1----"
    , testCase "mac2Label is correct" $ do
        mac2Label @?= "cookie--"
    ]

--------------------------------------------------------------------------------
-- Message Type Tests
--------------------------------------------------------------------------------

messageTypeTests :: TestTree
messageTypeTests =
  testGroup
    "Message Types"
    [ testCase "messageTypeByte for HandshakeInit is 1" $ do
        messageTypeByte MsgTypeHandshakeInit @?= 1
    , testCase "messageTypeByte for HandshakeResponse is 2" $ do
        messageTypeByte MsgTypeHandshakeResponse @?= 2
    , testCase "messageTypeByte for CookieReply is 3" $ do
        messageTypeByte MsgTypeCookieReply @?= 3
    , testCase "messageTypeByte for TransportData is 4" $ do
        messageTypeByte MsgTypeTransportData @?= 4
    , testCase "messageTypeFromByte roundtrips" $ do
        messageTypeFromByte 1 @?= Just MsgTypeHandshakeInit
        messageTypeFromByte 2 @?= Just MsgTypeHandshakeResponse
        messageTypeFromByte 3 @?= Just MsgTypeCookieReply
        messageTypeFromByte 4 @?= Just MsgTypeTransportData
    , testCase "messageTypeFromByte rejects invalid" $ do
        messageTypeFromByte 0 @?= Nothing
        messageTypeFromByte 5 @?= Nothing
        messageTypeFromByte 255 @?= Nothing
    ]

--------------------------------------------------------------------------------
-- Parsing Tests
--------------------------------------------------------------------------------

parsingTests :: TestTree
parsingTests =
  testGroup
    "Parsing"
    [ testCase "parseMessage extracts type and payload" $ do
        let msg = BS.pack [1, 0, 0, 0] <> "payload"
        case parseMessage msg of
          Left err -> assertFailure err
          Right (msgType, payload) -> do
            msgType @?= MsgTypeHandshakeInit
            payload @?= "payload"
    , testCase "parseMessage rejects short message" $ do
        case parseMessage (BS.pack [1, 0, 0]) of
          Left _ -> return ()
          Right _ -> assertFailure "Should have failed"
    , testCase "parseMessage rejects invalid reserved bytes" $ do
        case parseMessage (BS.pack [1, 1, 0, 0]) of
          Left _ -> return ()
          Right _ -> assertFailure "Should have failed"
    , testCase "parseMessage rejects unknown type" $ do
        case parseMessage (BS.pack [99, 0, 0, 0]) of
          Left _ -> return ()
          Right _ -> assertFailure "Should have failed"
    , testCase "parseTransportData parses correctly" $ do
        let payload =
              putWord32LE 0x12345678 -- receiver index
                <> putWord64LE 0xABCDEF0123456789 -- counter
                <> "encrypted" -- encrypted packet
        case parseTransportData payload of
          Left err -> assertFailure err
          Right td -> do
            tdReceiverIndex td @?= 0x12345678
            tdCounter td @?= 0xABCDEF0123456789
            tdEncryptedPacket td @?= "encrypted"
    , testCase "parseTransportData rejects short message" $ do
        case parseTransportData (BS.replicate 11 0) of
          Left _ -> return ()
          Right _ -> assertFailure "Should have failed"
    , testCase "parseHandshakeInit parses valid message" $ do
        privKey <- generatePrivateKey
        let pubKey = derivePublicKey privKey
            payload =
              putWord32LE 0x12345678 -- sender index
                <> publicKeyToBytes pubKey -- ephemeral (32 bytes)
                <> BS.replicate 48 0xAA -- encrypted static
                <> BS.replicate 28 0xBB -- encrypted timestamp
                <> BS.replicate 16 0xCC -- mac1
                <> BS.replicate 16 0xDD -- mac2
        case parseHandshakeInit payload of
          Left err -> assertFailure err
          Right hi -> do
            hiSenderIndex hi @?= 0x12345678
            hiEphemeral hi @?= pubKey
            hiEncryptedStatic hi @?= BS.replicate 48 0xAA
            hiEncryptedTimestamp hi @?= BS.replicate 28 0xBB
            hiMac1 hi @?= BS.replicate 16 0xCC
            hiMac2 hi @?= BS.replicate 16 0xDD
    , testCase "parseHandshakeInit rejects wrong length" $ do
        case parseHandshakeInit (BS.replicate 143 0) of
          Left _ -> return ()
          Right _ -> assertFailure "Should have failed"
        case parseHandshakeInit (BS.replicate 145 0) of
          Left _ -> return ()
          Right _ -> assertFailure "Should have failed"
    , testCase "parseHandshakeResponse parses valid message" $ do
        privKey <- generatePrivateKey
        let pubKey = derivePublicKey privKey
            payload =
              putWord32LE 0x12345678 -- sender index
                <> putWord32LE 0x87654321 -- receiver index
                <> publicKeyToBytes pubKey -- ephemeral (32 bytes)
                <> BS.replicate 16 0xAA -- encrypted nothing
                <> BS.replicate 16 0xBB -- mac1
                <> BS.replicate 16 0xCC -- mac2
        case parseHandshakeResponse payload of
          Left err -> assertFailure err
          Right hr -> do
            hrSenderIndex hr @?= 0x12345678
            hrReceiverIndex hr @?= 0x87654321
            hrEphemeral hr @?= pubKey
            hrEncryptedNothing hr @?= BS.replicate 16 0xAA
            hrMac1 hr @?= BS.replicate 16 0xBB
            hrMac2 hr @?= BS.replicate 16 0xCC
    ]

--------------------------------------------------------------------------------
-- Serialization Tests
--------------------------------------------------------------------------------

serializationTests :: TestTree
serializationTests =
  testGroup
    "Serialization"
    [ testCase "serializeHandshakeInit produces correct length" $ do
        privKey <- generatePrivateKey
        let pubKey = derivePublicKey privKey
            hi =
              HandshakeInit
                { hiSenderIndex = 1
                , hiEphemeral = pubKey
                , hiEncryptedStatic = BS.replicate 48 0
                , hiEncryptedTimestamp = BS.replicate 28 0
                , hiMac1 = BS.replicate 16 0
                , hiMac2 = BS.replicate 16 0
                }
        BS.length (serializeHandshakeInit hi) @?= handshakeInitLen
    , testCase "serializeHandshakeInit sets correct type" $ do
        privKey <- generatePrivateKey
        let pubKey = derivePublicKey privKey
            hi =
              HandshakeInit
                { hiSenderIndex = 1
                , hiEphemeral = pubKey
                , hiEncryptedStatic = BS.replicate 48 0
                , hiEncryptedTimestamp = BS.replicate 28 0
                , hiMac1 = BS.replicate 16 0
                , hiMac2 = BS.replicate 16 0
                }
            serialized = serializeHandshakeInit hi
        BS.index serialized 0 @?= 1 -- Type
        BS.take 3 (BS.drop 1 serialized) @?= BS.replicate 3 0 -- Reserved
    , testCase "serializeHandshakeResponse produces correct length" $ do
        privKey <- generatePrivateKey
        let pubKey = derivePublicKey privKey
            hr =
              HandshakeResponse
                { hrSenderIndex = 1
                , hrReceiverIndex = 2
                , hrEphemeral = pubKey
                , hrEncryptedNothing = BS.replicate 16 0
                , hrMac1 = BS.replicate 16 0
                , hrMac2 = BS.replicate 16 0
                }
        BS.length (serializeHandshakeResponse hr) @?= handshakeResponseLen
    , testCase "serializeHandshakeResponse sets correct type" $ do
        privKey <- generatePrivateKey
        let pubKey = derivePublicKey privKey
            hr =
              HandshakeResponse
                { hrSenderIndex = 1
                , hrReceiverIndex = 2
                , hrEphemeral = pubKey
                , hrEncryptedNothing = BS.replicate 16 0
                , hrMac1 = BS.replicate 16 0
                , hrMac2 = BS.replicate 16 0
                }
            serialized = serializeHandshakeResponse hr
        BS.index serialized 0 @?= 2 -- Type
    , testCase "serializeTransportData sets correct type" $ do
        let td =
              TransportData
                { tdReceiverIndex = 1
                , tdCounter = 0
                , tdEncryptedPacket = "encrypted"
                }
            serialized = serializeTransportData td
        BS.index serialized 0 @?= 4 -- Type
    , testCase "serializeTransportData produces correct header length" $ do
        let td =
              TransportData
                { tdReceiverIndex = 1
                , tdCounter = 0
                , tdEncryptedPacket = ""
                }
            serialized = serializeTransportData td
        BS.length serialized @?= transportHeaderLen
    ]

--------------------------------------------------------------------------------
-- Roundtrip Tests
--------------------------------------------------------------------------------

roundtripTests :: TestTree
roundtripTests =
  testGroup
    "Roundtrip"
    [ testCase "HandshakeInit roundtrips" $ do
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
        case parseMessage serialized of
          Left err -> assertFailure err
          Right (msgType, payload) -> do
            msgType @?= MsgTypeHandshakeInit
            case parseHandshakeInit payload of
              Left err -> assertFailure err
              Right hi' -> hi' @?= hi
    , testCase "HandshakeResponse roundtrips" $ do
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
        case parseMessage serialized of
          Left err -> assertFailure err
          Right (msgType, payload) -> do
            msgType @?= MsgTypeHandshakeResponse
            case parseHandshakeResponse payload of
              Left err -> assertFailure err
              Right hr' -> hr' @?= hr
    , testCase "TransportData roundtrips" $ do
        let td =
              TransportData
                { tdReceiverIndex = 0x12345678
                , tdCounter = 0xABCDEF0123456789
                , tdEncryptedPacket = "encrypted packet data"
                }
            serialized = serializeTransportData td
        case parseMessage serialized of
          Left err -> assertFailure err
          Right (msgType, payload) -> do
            msgType @?= MsgTypeTransportData
            case parseTransportData payload of
              Left err -> assertFailure err
              Right td' -> td' @?= td
    ]

--------------------------------------------------------------------------------
-- Transport Tests
--------------------------------------------------------------------------------

transportTests :: TestTree
transportTests =
  testGroup
    "Transport Encryption"
    [ testCase "encryptTransport/decryptTransport roundtrip" $ do
        let sendKey = kdf1 "test" "send"
            recvKey = kdf1 "test" "recv"
            keys =
              SessionKeys
                { skSend = CipherState sendKey 0
                , skReceive = CipherState recvKey 0
                }
            plaintext = "Hello, WireGuard transport!"
            counter = 42
            encrypted = encryptTransport keys counter plaintext
        case decryptTransport keys counter encrypted of
          Nothing -> assertFailure "Decryption failed"
          Just decrypted -> decrypted @?= plaintext
    , testCase "decryptTransport fails with wrong key" $ do
        let sendKey1 = kdf1 "test1" "send"
            sendKey2 = kdf1 "test2" "send"
            recvKey = kdf1 "test" "recv"
            keys1 =
              SessionKeys
                { skSend = CipherState sendKey1 0
                , skReceive = CipherState recvKey 0
                }
            keys2 =
              SessionKeys
                { skSend = CipherState sendKey2 0
                , skReceive = CipherState recvKey 0
                }
            plaintext = "Hello, WireGuard transport!"
            encrypted = encryptTransport keys1 0 plaintext
        decryptTransport keys2 0 encrypted @?= Nothing
    , testCase "decryptTransport fails with wrong counter" $ do
        let sendKey = kdf1 "test" "send"
            recvKey = kdf1 "test" "recv"
            keys =
              SessionKeys
                { skSend = CipherState sendKey 0
                , skReceive = CipherState recvKey 0
                }
            plaintext = "Hello, WireGuard transport!"
            encrypted = encryptTransport keys 0 plaintext
        decryptTransport keys 1 encrypted @?= Nothing
    , testCase "transport encryption adds tag" $ do
        let sendKey = kdf1 "test" "send"
            keys =
              SessionKeys
                { skSend = CipherState sendKey 0
                , skReceive = CipherState sendKey 0
                }
            plaintext = "test"
            encrypted = encryptTransport keys 0 plaintext
        BS.length encrypted @?= BS.length plaintext + tagLen
    ]

--------------------------------------------------------------------------------
-- MAC Tests
--------------------------------------------------------------------------------

macTests :: TestTree
macTests =
  testGroup
    "MAC Computation"
    [ testCase "computeMac1 produces 16 bytes" $ do
        privKey <- generatePrivateKey
        let pubKey = derivePublicKey privKey
            msg = BS.replicate 100 0
            mac1 = computeMac1 pubKey msg
        BS.length mac1 @?= 16
    , testCase "computeMac1 is deterministic" $ do
        privKey <- generatePrivateKey
        let pubKey = derivePublicKey privKey
            msg = BS.replicate 100 0
            mac1a = computeMac1 pubKey msg
            mac1b = computeMac1 pubKey msg
        mac1a @?= mac1b
    , testCase "computeMac1 differs for different keys" $ do
        privKey1 <- generatePrivateKey
        privKey2 <- generatePrivateKey
        let pubKey1 = derivePublicKey privKey1
            pubKey2 = derivePublicKey privKey2
            msg = BS.replicate 100 0
            mac1a = computeMac1 pubKey1 msg
            mac1b = computeMac1 pubKey2 msg
        mac1a /= mac1b @? "Different keys should produce different MACs"
    , testCase "computeMac2 produces 16 bytes" $ do
        let cookie = BS.replicate 16 0xAA
            msg = BS.replicate 100 0
            mac2 = computeMac2 cookie msg
        BS.length mac2 @?= 16
    , testCase "computeMac2 is deterministic" $ do
        let cookie = BS.replicate 16 0xAA
            msg = BS.replicate 100 0
            mac2a = computeMac2 cookie msg
            mac2b = computeMac2 cookie msg
        mac2a @?= mac2b
    ]

--------------------------------------------------------------------------------
-- Bits Tests
--------------------------------------------------------------------------------

bitsTests :: TestTree
bitsTests =
  testGroup
    "Bit Manipulation"
    [ testCase "putWord32LE/getWord32LE roundtrip" $ do
        let values = [0, 1, 0x12345678, 0xFFFFFFFF] :: [Word32]
        forM_ values $ \v -> do
          let bs = putWord32LE v
          getWord32LE bs 0 @?= v
    , testCase "putWord64LE/getWord64LE roundtrip" $ do
        let values = [0, 1, 0x123456789ABCDEF0, 0xFFFFFFFFFFFFFFFF] :: [Word64]
        forM_ values $ \v -> do
          let bs = putWord64LE v
          getWord64LE bs 0 @?= v
    , testCase "little-endian encoding is correct" $ do
        let w32 = 0x04030201 :: Word32
            bs32 = putWord32LE w32
        BS.unpack bs32 @?= [0x01, 0x02, 0x03, 0x04]

        let w64 = 0x0807060504030201 :: Word64
            bs64 = putWord64LE w64
        BS.unpack bs64 @?= [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    ]
 where
  forM_ xs f = mapM_ f xs

--------------------------------------------------------------------------------
-- Property Tests
--------------------------------------------------------------------------------

propertyTests :: TestTree
propertyTests =
  testGroup
    "Property Tests"
    [ testProperty "Word32 roundtrips" prop_word32Roundtrip
    , testProperty "Word64 roundtrips" prop_word64Roundtrip
    , testProperty "transport encryption roundtrips" prop_transportRoundtrip
    ]

prop_word32Roundtrip :: Word32 -> Property
prop_word32Roundtrip w =
  let bs = putWord32LE w
   in getWord32LE bs 0 === w

prop_word64Roundtrip :: Word64 -> Property
prop_word64Roundtrip w =
  let bs = putWord64LE w
   in getWord64LE bs 0 === w

prop_transportRoundtrip :: Property
prop_transportRoundtrip = ioProperty $ do
  privKey <- generatePrivateKey
  let symKey = kdf1 (publicKeyToBytes $ derivePublicKey privKey) "test"
      keys =
        SessionKeys
          { skSend = CipherState symKey 0
          , skReceive = CipherState symKey 0
          }
      plaintext = "property test plaintext"
      counter = 12345
  case decryptTransport keys counter (encryptTransport keys counter plaintext) of
    Nothing -> return $ property False
    Just decrypted -> return $ decrypted === plaintext
