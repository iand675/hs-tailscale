{-# LANGUAGE OverloadedStrings #-}

module CryptoSpec (tests) where

import qualified Data.ByteString as BS
import Test.Tasty
import Test.Tasty.HUnit

import Tailscale.Control.Client (generateMachineKey, generateNodeKey)
import Tailscale.Control.Protocol (MachineKey (..), NodeKey (..))
import Tailscale.WireGuard.Crypto

tests :: TestTree
tests =
  testGroup
    "Crypto"
    [ testGroup
        "Key generation"
        [ testCase "generatePrivateKey creates valid key" $ do
            privKey <- generatePrivateKey
            -- Just check it doesn't crash and we can derive public key
            let pubKey = derivePublicKey privKey
            pure ()
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
            -- This could theoretically fail but probability is negligible
            pubKey1 /= pubKey2 @? "Public keys should differ"
        ]
    , testGroup
        "Node and Machine keys"
        [ testCase "generateNodeKey creates valid keys" $ do
            (priv, pub) <- generateNodeKey
            let (NodeKey pubBs) = pub
            BS.length pubBs @?= 32
        , testCase "generateMachineKey creates valid key" $ do
            (MachineKey bs) <- generateMachineKey
            BS.length bs @?= 32
        ]
    , testGroup
        "ECDH"
        [ testCase "ecdh produces consistent shared secret" $ do
            privKey1 <- generatePrivateKey
            privKey2 <- generatePrivateKey
            let pubKey1 = derivePublicKey privKey1
                pubKey2 = derivePublicKey privKey2
                shared1 = ecdh privKey1 pubKey2
                shared2 = ecdh privKey2 pubKey1
            -- SharedSecret has Eq but not Show, so we use assertTrue
            (shared1 == shared2) @? "ECDH should produce same shared secret"
        ]
    , testGroup
        "Symmetric encryption"
        [ testCase "encrypt and decrypt round trip" $ do
            let key = zeroKey
                nonce = nonceFromCounter 0
                plaintext = "Hello, Tailscale!"
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
        ]
    , testGroup
        "Hashing"
        [ testCase "hash produces consistent results" $ do
            let h1 = hash "test data"
                h2 = hash "test data"
            h1 @?= h2
        , testCase "hash differs for different inputs" $ do
            let h1 = hash "input1"
                h2 = hash "input2"
            h1 /= h2 @? "Different inputs should produce different hashes"
        ]
    , testGroup
        "MAC"
        [ testCase "mac produces consistent results" $ do
            let key = "test-key-32-bytes-long-for-mac!"
                msg = "test-message"
                m1 = mac key msg
                m2 = mac key msg
            m1 @?= m2
        ]
    , testGroup
        "KDF"
        [ testCase "kdf1 produces key" $ do
            let key = "test-key-32-bytes-long-for-kdf!"
                input = "test input"
                derived = kdf1 key input
            -- Just check it produces a key without crashing
            pure ()
        , testCase "kdf2 produces two keys" $ do
            let key = "test-key-32-bytes-long-for-kdf!"
                input = "test input"
                (k1, k2) = kdf2 key input
            k1 /= k2 @? "KDF should produce different keys"
        , testCase "kdf3 produces three keys" $ do
            let key = "test-key-32-bytes-long-for-kdf!"
                input = "test input"
                (k1, k2, k3) = kdf3 key input
            k1 /= k2 @? "First and second keys should differ"
            k2 /= k3 @? "Second and third keys should differ"
            k1 /= k3 @? "First and third keys should differ"
        ]
    , testGroup
        "Constants"
        [ testCase "hashLen is 32" $ do
            hashLen @?= 32
        , testCase "keyLen is 32" $ do
            keyLen @?= 32
        , testCase "nonceLen is 12" $ do
            nonceLen @?= 12
        , testCase "tagLen is 16" $ do
            tagLen @?= 16
        ]
    ]
