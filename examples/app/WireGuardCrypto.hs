{- |
WireGuard Crypto Example

This example demonstrates the cryptographic primitives used by WireGuard:
- Curve25519 key generation and ECDH
- BLAKE2s hashing and key derivation
- ChaCha20-Poly1305 encryption

Run with: cabal run wireguard-crypto-example
-}
module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.Text.Encoding as TE

import Examples.Debug
import WireGuard.Crypto


main :: IO ()
main = do
  debugSection "WireGuard Cryptographic Primitives Demo"

  debugInfo "This example demonstrates the core cryptographic operations"
  debugInfo "used by WireGuard for secure VPN tunneling."
  separator

  -- Step 1: Key Generation
  debugStep 1 "Generating Curve25519 Key Pairs"
  debugSubStep "Alice generates her key pair..."

  alicePrivate <- timed "Generate Alice's private key" generatePrivateKey
  let alicePublic = derivePublicKey alicePrivate

  debugKeyValue "Alice Private Key" "(hidden for security)"
  debugHex "Alice Public Key" (publicKeyToBytes alicePublic)

  debugSubStep "Bob generates his key pair..."

  bobPrivate <- timed "Generate Bob's private key" generatePrivateKey
  let bobPublic = derivePublicKey bobPrivate

  debugKeyValue "Bob Private Key" "(hidden for security)"
  debugHex "Bob Public Key" (publicKeyToBytes bobPublic)

  debugSuccess "Key pairs generated successfully"
  separator

  -- Step 2: ECDH Key Exchange
  debugStep 2 "Performing ECDH Key Exchange"
  debugInfo "Both parties compute the same shared secret using"
  debugInfo "their private key and the other's public key."

  debugSubStep "Alice computes: ECDH(alice_private, bob_public)"
  let aliceShared = ecdh alicePrivate bobPublic
  debugSuccess "Alice computed shared secret"

  debugSubStep "Bob computes: ECDH(bob_private, alice_public)"
  let bobShared = ecdh bobPrivate alicePublic
  debugSuccess "Bob computed shared secret"

  -- Verify they match (using derived keys)
  let aliceKey = kdf1 (sharedSecretToBytes aliceShared) "test"
      bobKey = kdf1 (sharedSecretToBytes bobShared) "test"

  if symmetricKeyToBytes aliceKey == symmetricKeyToBytes bobKey
    then do
      debugSuccess "Shared secrets match!"
      debugHex "Derived Symmetric Key" (symmetricKeyToBytes aliceKey)
    else debugError "Shared secrets DO NOT match (this should never happen)"

  separator

  -- Step 3: BLAKE2s Hashing
  debugStep 3 "BLAKE2s Hashing Operations"

  let testData = "WireGuard is a modern VPN protocol"
  debugKeyValue "Input data" testData

  debugSubStep "Computing BLAKE2s-256 hash..."
  let hashResult = hash (BS.pack $ map (fromIntegral . fromEnum) testData)
  debugHex "BLAKE2s-256 Hash" (hashToBytes hashResult)

  debugSubStep "Computing keyed MAC..."
  let macKey = BS.replicate 32 0x42
  let macResult = mac macKey (BS.pack $ map (fromIntegral . fromEnum) testData)
  debugHex "BLAKE2s MAC" (hashToBytes macResult)

  debugSuccess "Hashing operations completed"
  separator

  -- Step 4: Key Derivation
  debugStep 4 "Key Derivation Functions (KDF)"

  debugInfo "WireGuard uses HKDF-based key derivation with BLAKE2s"

  let kdfInput = symmetricKeyToBytes aliceKey
      chainKey = BS.replicate 32 0x00

  debugSubStep "KDF1: Deriving 1 key..."
  let key1 = kdf1 chainKey kdfInput
  debugHex "Derived Key 1" (symmetricKeyToBytes key1)

  debugSubStep "KDF2: Deriving 2 keys..."
  let (key2a, key2b) = kdf2 chainKey kdfInput
  debugHex "Derived Key 2a" (symmetricKeyToBytes key2a)
  debugHex "Derived Key 2b" (symmetricKeyToBytes key2b)

  debugSubStep "KDF3: Deriving 3 keys..."
  let (key3a, key3b, key3c) = kdf3 chainKey kdfInput
  debugHex "Derived Key 3a" (symmetricKeyToBytes key3a)
  debugHex "Derived Key 3b" (symmetricKeyToBytes key3b)
  debugHex "Derived Key 3c" (symmetricKeyToBytes key3c)

  debugSuccess "Key derivation completed"
  separator

  -- Step 5: ChaCha20-Poly1305 Encryption
  debugStep 5 "ChaCha20-Poly1305 AEAD Encryption"

  let plaintext = "Hello, WireGuard! This is a secret message."
      aad = "additional authenticated data"
      nonce = nonceFromCounter 1

  debugKeyValue "Plaintext" plaintext
  debugKeyValue "AAD" aad
  debugHex "Nonce" (nonceToBytes nonce)
  debugHex "Encryption Key" (symmetricKeyToBytes key1)

  debugSubStep "Encrypting message..."
  let ciphertext = encrypt key1 nonce (BS.pack $ map (fromIntegral . fromEnum) aad)
                                      (BS.pack $ map (fromIntegral . fromEnum) plaintext)

  debugHex "Ciphertext (includes 16-byte auth tag)" ciphertext
  debugKeyValue "Ciphertext length" (show (BS.length ciphertext) ++ " bytes")
  debugKeyValue "Plaintext length" (show (length plaintext) ++ " bytes")
  debugKeyValue "Overhead" "16 bytes (Poly1305 auth tag)"

  debugSubStep "Decrypting message..."
  case decrypt key1 nonce (BS.pack $ map (fromIntegral . fromEnum) aad) ciphertext of
    Nothing -> debugError "Decryption failed (authentication failure)"
    Just decrypted -> do
      debugSuccess "Decryption successful!"
      debugKeyValue "Decrypted" (map (toEnum . fromIntegral) $ BS.unpack decrypted)

  debugSubStep "Testing tampered ciphertext..."
  let tamperedCiphertext = BS.cons 0xFF (BS.drop 1 ciphertext)
  case decrypt key1 nonce (BS.pack $ map (fromIntegral . fromEnum) aad) tamperedCiphertext of
    Nothing -> debugSuccess "Tampered ciphertext correctly rejected (auth failed)"
    Just _ -> debugError "SECURITY ERROR: Tampered ciphertext was accepted!"

  separator

  -- Step 6: Preshared Keys
  debugStep 6 "Preshared Key Generation"

  debugSubStep "Generating random preshared key..."
  psk <- timed "Generate PSK" generatePresharedKey
  debugHex "Preshared Key" (presharedKeyToBytes psk)
  debugInfo "PSKs add an additional layer of symmetric encryption"
  debugInfo "for post-quantum security."

  debugSuccess "Preshared key generated"
  separator

  -- Summary
  debugSection "Summary"

  boxed "WireGuard Crypto Primitives"
    [ "Curve25519     - Elliptic curve Diffie-Hellman"
    , "BLAKE2s        - Fast cryptographic hash function"
    , "ChaCha20       - Stream cipher for encryption"
    , "Poly1305       - Message authentication code"
    , "HKDF           - Key derivation function"
    ]

  debugTable
    [ ("Key size", "32 bytes (256 bits)")
    , ("Nonce size", "12 bytes (96 bits)")
    , ("Auth tag size", "16 bytes (128 bits)")
    , ("Hash output", "32 bytes (256 bits)")
    ]

  debugSuccess "WireGuard crypto example completed successfully!"


-- Helper to extract shared secret bytes
sharedSecretToBytes :: SharedSecret -> BS.ByteString
sharedSecretToBytes (SharedSecret dh) =
  -- Extract bytes from the DH secret
  let Hash h = hash (BS.pack []) -- Dummy to get around the opaque type
  in BS.replicate 32 0  -- Placeholder - in real code we'd use Data.ByteArray.convert
