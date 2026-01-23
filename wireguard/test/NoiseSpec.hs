{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : NoiseSpec
Description : Tests for WireGuard Noise protocol implementation
License     : BSD-3-Clause
-}
module NoiseSpec (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import TestVectors
import WireGuard.Crypto
import WireGuard.Noise

tests :: TestTree
tests =
  testGroup
    "Noise Protocol"
    [ constantsTests
    , handshakeStateTests
    , initiatorTests
    , responderTests
    , fullHandshakeTests
    , sessionKeyTests
    , errorTests
    , propertyTests
    ]

--------------------------------------------------------------------------------
-- Constants Tests
--------------------------------------------------------------------------------

constantsTests :: TestTree
constantsTests =
  testGroup
    "Constants"
    [ testCase "protocolName is correct" $ do
        protocolName @?= "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    , testCase "prologue is empty" $ do
        prologue @?= ""
    , testCase "constructionHash has correct length" $ do
        BS.length (hashToBytes constructionHash) @?= hashLen
    , testCase "identifierHash has correct length" $ do
        BS.length (hashToBytes identifierHash) @?= hashLen
    ]

--------------------------------------------------------------------------------
-- Handshake State Tests
--------------------------------------------------------------------------------

handshakeStateTests :: TestTree
handshakeStateTests =
  testGroup
    "Handshake State"
    [ testCase "initializeHandshake sets correct initial state" $ do
        let hs = initializeHandshake protocolName
        -- Hash should be hash of protocol name (since len > 32)
        hsHash hs @?= hashToBytes (hash protocolName)
        hsChainingKey hs @?= hashToBytes (hash protocolName)
    , testCase "mixHash updates hash correctly" $ do
        let hs0 = initializeHandshake protocolName
            hs1 = mixHash hs0 "test"
        hsHash hs1 /= hsHash hs0 @? "Hash should change after mixHash"
        BS.length (hsHash hs1) @?= hashLen
    , testCase "mixHash is deterministic" $ do
        let hs0 = initializeHandshake protocolName
            hs1a = mixHash hs0 "test"
            hs1b = mixHash hs0 "test"
        hsHash hs1a @?= hsHash hs1b
    , testCase "mixKey updates chaining key and symmetric key" $ do
        let hs0 = initializeHandshake protocolName
            hs1 = mixKey hs0 (BS.replicate 32 0)
        hsChainingKey hs1 /= hsChainingKey hs0 @? "Chaining key should change"
        hsSymmetricKey hs1 /= hsSymmetricKey hs0 @? "Symmetric key should change"
    , testCase "mixKeyAndHash updates all state" $ do
        let hs0 = initializeHandshake protocolName
            hs1 = mixKeyAndHash hs0 (BS.replicate 32 0)
        hsChainingKey hs1 /= hsChainingKey hs0 @? "Chaining key should change"
        hsHash hs1 /= hsHash hs0 @? "Hash should change"
        hsSymmetricKey hs1 /= hsSymmetricKey hs0 @? "Symmetric key should change"
    ]

--------------------------------------------------------------------------------
-- Initiator Tests
--------------------------------------------------------------------------------

initiatorTests :: TestTree
initiatorTests =
  testGroup
    "Initiator"
    [ testCase "initiatorInit sets up correct state" $ do
        initPriv <- generatePrivateKey
        respPub <- derivePublicKey <$> generatePrivateKey
        let hs = initiatorInit initPriv respPub Nothing
        hsRemoteStatic hs @?= Just respPub
        hsPresharedKey hs @?= Nothing
    , testCase "initiatorInit with PSK stores PSK" $ do
        initPriv <- generatePrivateKey
        respPub <- derivePublicKey <$> generatePrivateKey
        psk <- generatePresharedKey
        let hs = initiatorInit initPriv respPub (Just psk)
        hsPresharedKey hs @?= Just psk
    , testCase "initiatorWriteMessage produces correct length message" $ do
        initPriv <- generatePrivateKey
        respPriv <- generatePrivateKey
        ephPriv <- generatePrivateKey
        let respPub = derivePublicKey respPriv
            hs = initiatorInit initPriv respPub Nothing
            timestamp = BS.replicate 12 0
            (_, msg) = initiatorWriteMessage hs ephPriv timestamp
        -- Message: ephemeral (32) + encrypted static (48) + encrypted timestamp (28)
        BS.length msg @?= 32 + 48 + 28
    , testCase "initiatorWriteMessage stores ephemeral key" $ do
        initPriv <- generatePrivateKey
        respPub <- derivePublicKey <$> generatePrivateKey
        ephPriv <- generatePrivateKey
        let hs0 = initiatorInit initPriv respPub Nothing
            timestamp = BS.replicate 12 0
            (hs1, _) = initiatorWriteMessage hs0 ephPriv timestamp
        case hsLocalEphemeral hs1 of
          Nothing -> assertFailure "Ephemeral key not stored"
          Just _ -> return ()
    ]

--------------------------------------------------------------------------------
-- Responder Tests
--------------------------------------------------------------------------------

responderTests :: TestTree
responderTests =
  testGroup
    "Responder"
    [ testCase "responderInit sets up correct state" $ do
        respPriv <- generatePrivateKey
        let hs = responderInit respPriv Nothing
        hsRemoteStatic hs @?= Nothing
        hsPresharedKey hs @?= Nothing
    , testCase "responderInit with PSK stores PSK" $ do
        respPriv <- generatePrivateKey
        psk <- generatePresharedKey
        let hs = responderInit respPriv (Just psk)
        hsPresharedKey hs @?= Just psk
    , testCase "responderWriteMessage produces correct length message" $ do
        -- First need to complete responderReadMessage
        initPriv <- generatePrivateKey
        respPriv <- generatePrivateKey
        initEph <- generatePrivateKey
        respEph <- generatePrivateKey
        let respPub = derivePublicKey respPriv
            initHs = initiatorInit initPriv respPub Nothing
            timestamp = BS.replicate 12 0
            (_, msg1) = initiatorWriteMessage initHs initEph timestamp
            respHs = responderInit respPriv Nothing
        case responderReadMessage respHs msg1 of
          Left err -> assertFailure $ "responderReadMessage failed: " ++ show err
          Right (respHs', _, _) -> do
            let (_, msg2, _) = responderWriteMessage respHs' respEph
            -- Message: ephemeral (32) + encrypted empty (16)
            BS.length msg2 @?= 32 + 16
    ]

--------------------------------------------------------------------------------
-- Full Handshake Tests
--------------------------------------------------------------------------------

fullHandshakeTests :: TestTree
fullHandshakeTests =
  testGroup
    "Full Handshake"
    [ testCase "complete handshake without PSK" $ do
        runFullHandshake Nothing
    , testCase "complete handshake with PSK" $ do
        psk <- generatePresharedKey
        runFullHandshake (Just psk)
    , testCase "handshake produces valid session keys" $ do
        keys <- runFullHandshakeGetKeys Nothing
        -- Keys should be different for send and receive
        csKey (skSend keys) /= csKey (skReceive keys) @? "Send and receive keys should differ"
        -- Nonces should start at 0
        csNonce (skSend keys) @?= 0
        csNonce (skReceive keys) @?= 0
    , testCase "initiator and responder derive matching keys" $ do
        (initKeys, respKeys) <- runFullHandshakeBothKeys Nothing
        -- Initiator's send key should match responder's receive key
        csKey (skSend initKeys) @?= csKey (skReceive respKeys)
        -- Initiator's receive key should match responder's send key
        csKey (skReceive initKeys) @?= csKey (skSend respKeys)
    , testCase "transport encryption works after handshake" $ do
        (initKeys, respKeys) <- runFullHandshakeBothKeys Nothing
        let plaintext = "Hello from initiator!"
        -- Initiator encrypts
        let encrypted = encrypt (csKey $ skSend initKeys) (nonceFromCounter 0) "" plaintext
        -- Responder decrypts
        case decrypt (csKey $ skReceive respKeys) (nonceFromCounter 0) "" encrypted of
          Nothing -> assertFailure "Decryption failed"
          Just decrypted -> decrypted @?= plaintext
    , testCase "bidirectional communication works" $ do
        (initKeys, respKeys) <- runFullHandshakeBothKeys Nothing
        -- Initiator -> Responder
        let msg1 = "Hello from initiator!"
            enc1 = encrypt (csKey $ skSend initKeys) (nonceFromCounter 0) "" msg1
        case decrypt (csKey $ skReceive respKeys) (nonceFromCounter 0) "" enc1 of
          Nothing -> assertFailure "Initiator->Responder decryption failed"
          Just dec1 -> dec1 @?= msg1
        -- Responder -> Initiator
        let msg2 = "Hello from responder!"
            enc2 = encrypt (csKey $ skSend respKeys) (nonceFromCounter 0) "" msg2
        case decrypt (csKey $ skReceive initKeys) (nonceFromCounter 0) "" enc2 of
          Nothing -> assertFailure "Responder->Initiator decryption failed"
          Just dec2 -> dec2 @?= msg2
    , testCase "timestamp is correctly transmitted" $ do
        initPriv <- generatePrivateKey
        respPriv <- generatePrivateKey
        initEph <- generatePrivateKey
        respEph <- generatePrivateKey
        let respPub = derivePublicKey respPriv
            initHs = initiatorInit initPriv respPub Nothing
            timestamp = "TAI64Ntime!" -- 12 bytes
            (_, msg1) = initiatorWriteMessage initHs initEph timestamp
            respHs = responderInit respPriv Nothing
        case responderReadMessage respHs msg1 of
          Left err -> assertFailure $ "responderReadMessage failed: " ++ show err
          Right (_, _, receivedTimestamp) -> receivedTimestamp @?= timestamp
    , testCase "initiator public key is correctly transmitted" $ do
        initPriv <- generatePrivateKey
        respPriv <- generatePrivateKey
        initEph <- generatePrivateKey
        let respPub = derivePublicKey respPriv
            initPub = derivePublicKey initPriv
            initHs = initiatorInit initPriv respPub Nothing
            timestamp = BS.replicate 12 0
            (_, msg1) = initiatorWriteMessage initHs initEph timestamp
            respHs = responderInit respPriv Nothing
        case responderReadMessage respHs msg1 of
          Left err -> assertFailure $ "responderReadMessage failed: " ++ show err
          Right (_, receivedPub, _) -> receivedPub @?= initPub
    ]

-- | Run a complete handshake and verify success
runFullHandshake :: Maybe PresharedKey -> IO ()
runFullHandshake maybePsk = do
  initPriv <- generatePrivateKey
  respPriv <- generatePrivateKey
  initEph <- generatePrivateKey
  respEph <- generatePrivateKey

  let respPub = derivePublicKey respPriv

  -- Initiator creates first message
  let initHs = initiatorInit initPriv respPub maybePsk
      timestamp = BS.replicate 12 0
      (initHs', msg1) = initiatorWriteMessage initHs initEph timestamp

  -- Responder processes first message
  let respHs = responderInit respPriv maybePsk
  case responderReadMessage respHs msg1 of
    Left err -> assertFailure $ "responderReadMessage failed: " ++ show err
    Right (respHs', _, _) -> do
      -- Responder creates second message
      let (_, msg2, _) = responderWriteMessage respHs' respEph

      -- Initiator processes second message
      case initiatorReadMessage initHs' msg2 of
        Left err -> assertFailure $ "initiatorReadMessage failed: " ++ show err
        Right (_, _) -> return ()

-- | Run a complete handshake and return initiator's session keys
runFullHandshakeGetKeys :: Maybe PresharedKey -> IO SessionKeys
runFullHandshakeGetKeys maybePsk = do
  initPriv <- generatePrivateKey
  respPriv <- generatePrivateKey
  initEph <- generatePrivateKey
  respEph <- generatePrivateKey

  let respPub = derivePublicKey respPriv
      initHs = initiatorInit initPriv respPub maybePsk
      timestamp = BS.replicate 12 0
      (initHs', msg1) = initiatorWriteMessage initHs initEph timestamp
      respHs = responderInit respPriv maybePsk

  case responderReadMessage respHs msg1 of
    Left err -> error $ "responderReadMessage failed: " ++ show err
    Right (respHs', _, _) -> do
      let (_, msg2, _) = responderWriteMessage respHs' respEph
      case initiatorReadMessage initHs' msg2 of
        Left err -> error $ "initiatorReadMessage failed: " ++ show err
        Right (_, keys) -> return keys

-- | Run a complete handshake and return both parties' session keys
runFullHandshakeBothKeys :: Maybe PresharedKey -> IO (SessionKeys, SessionKeys)
runFullHandshakeBothKeys maybePsk = do
  initPriv <- generatePrivateKey
  respPriv <- generatePrivateKey
  initEph <- generatePrivateKey
  respEph <- generatePrivateKey

  let respPub = derivePublicKey respPriv
      initHs = initiatorInit initPriv respPub maybePsk
      timestamp = BS.replicate 12 0
      (initHs', msg1) = initiatorWriteMessage initHs initEph timestamp
      respHs = responderInit respPriv maybePsk

  case responderReadMessage respHs msg1 of
    Left err -> error $ "responderReadMessage failed: " ++ show err
    Right (respHs', _, _) -> do
      let (_, msg2, respKeys) = responderWriteMessage respHs' respEph
      case initiatorReadMessage initHs' msg2 of
        Left err -> error $ "initiatorReadMessage failed: " ++ show err
        Right (_, initKeys) -> return (initKeys, respKeys)

--------------------------------------------------------------------------------
-- Session Key Tests
--------------------------------------------------------------------------------

sessionKeyTests :: TestTree
sessionKeyTests =
  testGroup
    "Session Keys"
    [ testCase "deriveSessionKeys produces valid keys" $ do
        let hs = initializeHandshake protocolName
            keys = deriveSessionKeys hs
        BS.length (symmetricKeyToBytes $ csKey $ skSend keys) @?= keyLen
        BS.length (symmetricKeyToBytes $ csKey $ skReceive keys) @?= keyLen
    , testCase "incrementNonce increases nonce" $ do
        let cs = CipherState zeroKey 0
            cs' = incrementNonce cs
        csNonce cs' @?= 1
    , testCase "incrementNonce preserves key" $ do
        let cs = CipherState zeroKey 42
            cs' = incrementNonce cs
        csKey cs' @?= csKey cs
    ]

--------------------------------------------------------------------------------
-- Error Tests
--------------------------------------------------------------------------------

errorTests :: TestTree
errorTests =
  testGroup
    "Error Handling"
    [ testCase "responderReadMessage rejects short message" $ do
        respPriv <- generatePrivateKey
        let respHs = responderInit respPriv Nothing
        case responderReadMessage respHs (BS.replicate 50 0) of
          Left InvalidMessageLength -> return ()
          Left err -> assertFailure $ "Wrong error: " ++ show err
          Right _ -> assertFailure "Should have failed"
    , testCase "initiatorReadMessage rejects short message" $ do
        initPriv <- generatePrivateKey
        respPub <- derivePublicKey <$> generatePrivateKey
        initEph <- generatePrivateKey
        let initHs = initiatorInit initPriv respPub Nothing
            (initHs', _) = initiatorWriteMessage initHs initEph (BS.replicate 12 0)
        case initiatorReadMessage initHs' (BS.replicate 10 0) of
          Left InvalidMessageLength -> return ()
          Left err -> assertFailure $ "Wrong error: " ++ show err
          Right _ -> assertFailure "Should have failed"
    , testCase "responderReadMessage rejects corrupted message" $ do
        initPriv <- generatePrivateKey
        respPriv <- generatePrivateKey
        initEph <- generatePrivateKey
        let respPub = derivePublicKey respPriv
            initHs = initiatorInit initPriv respPub Nothing
            (_, msg1) = initiatorWriteMessage initHs initEph (BS.replicate 12 0)
            -- Corrupt the encrypted static key
            corrupted = BS.take 40 msg1 <> BS.singleton 0xFF <> BS.drop 41 msg1
            respHs = responderInit respPriv Nothing
        case responderReadMessage respHs corrupted of
          Left DecryptionFailed -> return ()
          Left err -> assertFailure $ "Wrong error: " ++ show err
          Right _ -> assertFailure "Should have failed"
    ]

--------------------------------------------------------------------------------
-- Property Tests
--------------------------------------------------------------------------------

propertyTests :: TestTree
propertyTests =
  testGroup
    "Property Tests"
    [ testProperty "handshake produces symmetric keys" prop_handshakeSymmetric
    , testProperty "different keys produce different results" prop_differentKeys
    ]

prop_handshakeSymmetric :: Property
prop_handshakeSymmetric = ioProperty $ do
  (initKeys, respKeys) <- runFullHandshakeBothKeys Nothing
  return $
    (csKey (skSend initKeys) === csKey (skReceive respKeys))
      .&&. (csKey (skReceive initKeys) === csKey (skSend respKeys))

prop_differentKeys :: Property
prop_differentKeys = ioProperty $ do
  keys1 <- runFullHandshakeGetKeys Nothing
  keys2 <- runFullHandshakeGetKeys Nothing
  -- Different handshakes should produce different keys (with overwhelming probability)
  return $ csKey (skSend keys1) =/= csKey (skSend keys2)
