{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : CryptoSpec
Description : Tests for WireGuard cryptographic primitives
License     : BSD-3-Clause
-}
module CryptoSpec (tests) where

import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import TestVectors
import WireGuard.Crypto

tests :: TestTree
tests =
  testGroup
    "Crypto"
    [ keyGenerationTests
    , ecdhTests
    , encryptionTests
    , hashingTests
    , kdfTests
    , constantsTests
    , testVectorTests
    , propertyTests
    ]

--------------------------------------------------------------------------------
-- Key Generation Tests
--------------------------------------------------------------------------------

keyGenerationTests :: TestTree
keyGenerationTests =
  testGroup
    "Key Generation"
    [ testCase "generatePrivateKey creates valid key" $ do
        privKey <- generatePrivateKey
        let pubKey = derivePublicKey privKey
        BS.length (publicKeyToBytes pubKey) @?= 32
    , testCase "derivePublicKey produces consistent results" $ do
        privKey <- generatePrivateKey
        let pubKey1 = derivePublicKey privKey
            pubKey2 = derivePublicKey privKey
        pubKey1 @?= pubKey2
    , testCase "different private keys produce different public keys" $ do
        privKey1 <- generatePrivateKey
        privKey2 <- generatePrivateKey
        let pubKey1 = derivePublicKey privKey1
            pubKey2 = derivePublicKey privKey2
        pubKey1 /= pubKey2 @? "Public keys should differ"
    , testCase "generatePresharedKey creates 32-byte key" $ do
        psk <- generatePresharedKey
        BS.length (presharedKeyToBytes psk) @?= 32
    , testCase "privateKeyFromBytes roundtrips" $ do
        privKey <- generatePrivateKey
        let bs = privateKeyToBytes privKey
        case privateKeyFromBytes bs of
          Nothing -> assertFailure "Failed to parse private key"
          Just privKey' -> do
            let pub1 = derivePublicKey privKey
                pub2 = derivePublicKey privKey'
            pub1 @?= pub2
    , testCase "publicKeyFromBytes roundtrips" $ do
        privKey <- generatePrivateKey
        let pubKey = derivePublicKey privKey
            bs = publicKeyToBytes pubKey
        case publicKeyFromBytes bs of
          Nothing -> assertFailure "Failed to parse public key"
          Just pubKey' -> pubKey @?= pubKey'
    , testCase "invalid key bytes rejected" $ do
        privateKeyFromBytes "" @?= Nothing
        privateKeyFromBytes (BS.replicate 31 0) @?= Nothing
        publicKeyFromBytes "" @?= Nothing
        publicKeyFromBytes (BS.replicate 31 0) @?= Nothing
    ]

--------------------------------------------------------------------------------
-- ECDH Tests
--------------------------------------------------------------------------------

ecdhTests :: TestTree
ecdhTests =
  testGroup
    "ECDH"
    [ testCase "ecdh produces consistent shared secret" $ do
        privKey1 <- generatePrivateKey
        privKey2 <- generatePrivateKey
        let pubKey1 = derivePublicKey privKey1
            pubKey2 = derivePublicKey privKey2
            shared1 = ecdh privKey1 pubKey2
            shared2 = ecdh privKey2 pubKey1
        (shared1 == shared2) @? "ECDH should produce same shared secret"
    , testCase "Curve25519 test vectors" $ do
        -- RFC 7748 test vector
        let alicePriv = hexToBS "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
            bobPub = hexToBS "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
            expectedShared = hexToBS "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        case (privateKeyFromBytes alicePriv, publicKeyFromBytes bobPub) of
          (Just priv, Just pub) -> do
            let SharedSecret dhResult = ecdh priv pub
            BA.convert dhResult @?= expectedShared
          _ -> assertFailure "Failed to parse test vector keys"
    ]

--------------------------------------------------------------------------------
-- Encryption Tests
--------------------------------------------------------------------------------

encryptionTests :: TestTree
encryptionTests =
  testGroup
    "Symmetric Encryption (ChaCha20-Poly1305)"
    [ testCase "encrypt and decrypt round trip" $ do
        let key = zeroKey
            nonce = nonceFromCounter 0
            plaintext = "Hello, WireGuard!"
        case decrypt key nonce "" (encrypt key nonce "" plaintext) of
          Nothing -> assertFailure "Decryption failed"
          Just decrypted -> decrypted @?= plaintext
    , testCase "encrypt produces different output for different nonces" $ do
        let key = zeroKey
            plaintext = "Test message"
            nonce1 = nonceFromCounter 0
            nonce2 = nonceFromCounter 1
            ct1 = encrypt key nonce1 "" plaintext
            ct2 = encrypt key nonce2 "" plaintext
        ct1 /= ct2 @? "Different nonces should produce different ciphertext"
    , testCase "encrypt produces different output for different keys" $ do
        let key1 = zeroKey
            key2 = SymmetricKey (BS.replicate 31 0 <> BS.singleton 1)
            nonce = nonceFromCounter 0
            plaintext = "Test message"
            ct1 = encrypt key1 nonce "" plaintext
            ct2 = encrypt key2 nonce "" plaintext
        ct1 /= ct2 @? "Different keys should produce different ciphertext"
    , testCase "AAD affects authentication" $ do
        let key = zeroKey
            nonce = nonceFromCounter 0
            plaintext = "Test message"
            ct = encrypt key nonce "aad1" plaintext
        decrypt key nonce "aad2" ct @?= Nothing
        decrypt key nonce "aad1" ct @?= Just plaintext
    , testCase "tampered ciphertext fails authentication" $ do
        let key = zeroKey
            nonce = nonceFromCounter 0
            plaintext = "Test message"
            ct = encrypt key nonce "" plaintext
            tampered = BS.take 5 ct <> BS.singleton 0xFF <> BS.drop 6 ct
        decrypt key nonce "" tampered @?= Nothing
    , testCase "ciphertext includes 16-byte tag" $ do
        let key = zeroKey
            nonce = nonceFromCounter 0
            plaintext = "Test"
            ct = encrypt key nonce "" plaintext
        BS.length ct @?= BS.length plaintext + tagLen
    , testCase "empty plaintext produces only tag" $ do
        let key = zeroKey
            nonce = nonceFromCounter 0
            ct = encrypt key nonce "" ""
        BS.length ct @?= tagLen
    ]

--------------------------------------------------------------------------------
-- Hashing Tests
--------------------------------------------------------------------------------

hashingTests :: TestTree
hashingTests =
  testGroup
    "Hashing (BLAKE2s)"
    [ testCase "hash produces consistent results" $ do
        let h1 = hash "test data"
            h2 = hash "test data"
        h1 @?= h2
    , testCase "hash differs for different inputs" $ do
        let h1 = hash "input1"
            h2 = hash "input2"
        h1 /= h2 @? "Different inputs should produce different hashes"
    , testCase "hash produces 32 bytes" $ do
        let h = hash "test"
        BS.length (hashToBytes h) @?= hashLen
    , testCase "BLAKE2s test vector - empty" $ do
        let h = hash ""
            expected = hexToBS "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        hashToBytes h @?= expected
    , testCase "BLAKE2s test vector - abc" $ do
        let h = hash "abc"
            expected = hexToBS "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        hashToBytes h @?= expected
    , testCase "BLAKE2s test vector - quick brown fox" $ do
        let h = hash "The quick brown fox jumps over the lazy dog"
            expected = hexToBS "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812"
        hashToBytes h @?= expected
    , testCase "mac produces consistent results" $ do
        let key = "test-key-32-bytes-long-for-mac!"
            msg = "test-message"
            m1 = mac key msg
            m2 = mac key msg
        m1 @?= m2
    , testCase "mac differs for different keys" $ do
        let key1 = "test-key-32-bytes-long-for-mac1"
            key2 = "test-key-32-bytes-long-for-mac2"
            msg = "test-message"
            m1 = mac key1 msg
            m2 = mac key2 msg
        m1 /= m2 @? "Different keys should produce different MACs"
    ]

--------------------------------------------------------------------------------
-- KDF Tests
--------------------------------------------------------------------------------

kdfTests :: TestTree
kdfTests =
  testGroup
    "KDF"
    [ testCase "kdf1 produces 32-byte key" $ do
        let key = "test-key-32-bytes-long-for-kdf!"
            input = "test input"
            derived = kdf1 key input
        BS.length (symmetricKeyToBytes derived) @?= keyLen
    , testCase "kdf2 produces two different keys" $ do
        let key = "test-key-32-bytes-long-for-kdf!"
            input = "test input"
            (k1, k2) = kdf2 key input
        k1 /= k2 @? "KDF should produce different keys"
    , testCase "kdf3 produces three different keys" $ do
        let key = "test-key-32-bytes-long-for-kdf!"
            input = "test input"
            (k1, k2, k3) = kdf3 key input
        k1 /= k2 @? "First and second keys should differ"
        k2 /= k3 @? "Second and third keys should differ"
        k1 /= k3 @? "First and third keys should differ"
    , testCase "kdf is deterministic" $ do
        let key = "test-key"
            input = "test input"
            (k1a, k2a) = kdf2 key input
            (k1b, k2b) = kdf2 key input
        k1a @?= k1b
        k2a @?= k2b
    , testCase "kdf differs for different inputs" $ do
        let key = "test-key"
            (k1a, _) = kdf2 key "input1"
            (k1b, _) = kdf2 key "input2"
        k1a /= k1b @? "Different inputs should produce different keys"
    , testCase "KDF test vector - zero key, empty input" $ do
        let key = BS.replicate 32 0
            input = ""
            (k1, k2) = kdf2 key input
            expected1 = hexToBS "8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0"
            expected2 = hexToBS "58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e"
        symmetricKeyToBytes k1 @?= expected1
        symmetricKeyToBytes k2 @?= expected2
    ]

--------------------------------------------------------------------------------
-- Constants Tests
--------------------------------------------------------------------------------

constantsTests :: TestTree
constantsTests =
  testGroup
    "Constants"
    [ testCase "hashLen is 32" $ hashLen @?= 32
    , testCase "keyLen is 32" $ keyLen @?= 32
    , testCase "nonceLen is 12" $ nonceLen @?= 12
    , testCase "tagLen is 16" $ tagLen @?= 16
    , testCase "zeroKey is all zeros" $ do
        let zeros = BS.replicate 32 0
        symmetricKeyToBytes zeroKey @?= zeros
    , testCase "zeroPsk is all zeros" $ do
        let zeros = BS.replicate 32 0
        presharedKeyToBytes zeroPsk @?= zeros
    ]

--------------------------------------------------------------------------------
-- Test Vector Tests
--------------------------------------------------------------------------------

testVectorTests :: TestTree
testVectorTests =
  testGroup
    "Specification Test Vectors"
    [ testGroup "BLAKE2s" $ map mkBlake2sTest blake2sVectors
    , testGroup "Curve25519" $ map mkCurve25519Test curve25519Vectors
    ]
 where
  mkBlake2sTest Blake2sVector{..} =
    testCase ("BLAKE2s: " ++ show (BS.take 20 b2sInput) ++ "...") $ do
      let result = hash b2sInput
      hashToBytes result @?= b2sExpected

  mkCurve25519Test Curve25519Vector{..} =
    testCase "Curve25519 ECDH" $ do
      case (privateKeyFromBytes c25519PrivKey, publicKeyFromBytes c25519PubKey) of
        (Just priv, Just pub) -> do
          let SharedSecret dhResult = ecdh priv pub
          BA.convert dhResult @?= c25519SharedSecret
        _ -> assertFailure "Failed to parse test vector keys"

--------------------------------------------------------------------------------
-- Property Tests
--------------------------------------------------------------------------------

propertyTests :: TestTree
propertyTests =
  testGroup
    "Property Tests"
    [ testProperty "encrypt/decrypt roundtrip" prop_encryptDecryptRoundtrip
    , testProperty "ECDH commutativity" prop_ecdhCommutative
    , testProperty "hash deterministic" prop_hashDeterministic
    , testProperty "nonce construction" prop_nonceConstruction
    ]

prop_encryptDecryptRoundtrip :: Property
prop_encryptDecryptRoundtrip = ioProperty $ do
  key <- generatePrivateKey
  let symKey = kdf1 (publicKeyToBytes $ derivePublicKey key) "test"
      nonce = nonceFromCounter 42
      plaintext = "test plaintext for property"
  case decrypt symKey nonce "" (encrypt symKey nonce "" plaintext) of
    Nothing -> return $ property False
    Just decrypted -> return $ decrypted === plaintext

prop_ecdhCommutative :: Property
prop_ecdhCommutative = ioProperty $ do
  priv1 <- generatePrivateKey
  priv2 <- generatePrivateKey
  let pub1 = derivePublicKey priv1
      pub2 = derivePublicKey priv2
      shared1 = ecdh priv1 pub2
      shared2 = ecdh priv2 pub1
  return $ shared1 === shared2

prop_hashDeterministic :: BS.ByteString -> Property
prop_hashDeterministic input =
  hash input === hash input

prop_nonceConstruction :: Word64 -> Property
prop_nonceConstruction counter =
  let nonce = nonceFromCounter counter
   in BS.length (nonceToBytes nonce) === nonceLen
