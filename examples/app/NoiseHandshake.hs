{- |
Noise Protocol Handshake Example

This example demonstrates the Noise_IKpsk2 handshake pattern used by WireGuard:
- Initiator (client) and Responder (server) key setup
- Message 1: Initiator -> Responder (ephemeral key, encrypted static, timestamp)
- Message 2: Responder -> Initiator (ephemeral key, confirmation)
- Session key derivation for transport encryption

Run with: cabal run noise-handshake-example
-}
module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Word (Word64)

import Examples.Debug
import WireGuard.Crypto
import WireGuard.Noise


main :: IO ()
main = do
  debugSection "Noise_IKpsk2 Handshake Protocol Demo"

  debugInfo "WireGuard uses the Noise Protocol Framework with pattern:"
  debugInfo "  Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
  debugInfo ""
  debugInfo "Pattern description:"
  debugInfo "  <- s        (responder's static key is known)"
  debugInfo "  -> e, es, s, ss   (message 1)"
  debugInfo "  <- e, ee, se, psk (message 2)"
  separator

  -- Step 1: Generate Long-term Keys
  debugStep 1 "Generating Long-term Static Keys"

  debugSubStep "Generating Initiator (Client) static key pair..."
  initiatorStatic <- generatePrivateKey
  let initiatorStaticPub = derivePublicKey initiatorStatic
  debugHex "Initiator Static Public Key" (publicKeyToBytes initiatorStaticPub)

  debugSubStep "Generating Responder (Server) static key pair..."
  responderStatic <- generatePrivateKey
  let responderStaticPub = derivePublicKey responderStatic
  debugHex "Responder Static Public Key" (publicKeyToBytes responderStaticPub)

  debugSuccess "Static keys generated"
  separator

  -- Step 2: Optional Preshared Key
  debugStep 2 "Setting Up Preshared Key (Optional)"

  debugSubStep "Generating preshared key for additional security..."
  psk <- generatePresharedKey
  debugHex "Preshared Key" (presharedKeyToBytes psk)
  debugInfo "The PSK adds symmetric key material to the handshake"
  debugInfo "This provides post-quantum security if the PSK is secure"

  debugSuccess "Preshared key ready"
  separator

  -- Step 3: Initialize Handshake States
  debugStep 3 "Initializing Handshake States"

  debugSubStep "Initiator initializes handshake state..."
  let initiatorState0 = initiatorInit initiatorStatic responderStaticPub (Just psk)

  debugTable
    [ ("Protocol", show protocolName)
    , ("Local Static", "Initiator's private key")
    , ("Remote Static", "Responder's public key (known)")
    , ("Preshared Key", "Present")
    ]

  debugSubStep "Responder initializes handshake state..."
  let responderState0 = responderInit responderStatic (Just psk)

  debugTable
    [ ("Protocol", show protocolName)
    , ("Local Static", "Responder's private key")
    , ("Remote Static", "Unknown (will be learned)")
    , ("Preshared Key", "Present")
    ]

  debugSuccess "Handshake states initialized"
  separator

  -- Step 4: Message 1 (Initiator -> Responder)
  debugStep 4 "Message 1: Initiator -> Responder"

  debugInfo "Message 1 contains:"
  debugInfo "  - Initiator's ephemeral public key (32 bytes)"
  debugInfo "  - Encrypted initiator static public key (32 + 16 bytes)"
  debugInfo "  - Encrypted timestamp (12 + 16 bytes)"
  debugInfo ""

  debugSubStep "Generating initiator's ephemeral key..."
  initiatorEphemeral <- generatePrivateKey
  let initiatorEphemeralPub = derivePublicKey initiatorEphemeral
  debugHex "Initiator Ephemeral Public Key" (publicKeyToBytes initiatorEphemeralPub)

  debugSubStep "Creating TAI64N timestamp..."
  timestamp <- createTimestamp
  debugHex "Timestamp" timestamp

  debugSubStep "Creating handshake message 1..."
  let (initiatorState1, message1) = initiatorWriteMessage initiatorState0 initiatorEphemeral timestamp

  debugHex "Message 1" message1
  debugKeyValue "Message 1 Length" (show (BS.length message1) ++ " bytes")
  debugKeyValue "Expected" "32 + 48 + 28 = 108 bytes"

  debugSubStep "Message 1 breakdown:"
  let (msg1Ephemeral, msg1Rest) = BS.splitAt 32 message1
      (msg1EncStatic, msg1EncTimestamp) = BS.splitAt 48 msg1Rest
  debugHex "  [0:32]   Ephemeral Public Key" msg1Ephemeral
  debugHex "  [32:80]  Encrypted Static Key" msg1EncStatic
  debugHex "  [80:108] Encrypted Timestamp" msg1EncTimestamp

  debugSuccess "Message 1 created"
  separator

  -- Step 5: Responder Processes Message 1
  debugStep 5 "Responder Processes Message 1"

  debugSubStep "Responder reads and decrypts message 1..."
  case responderReadMessage responderState0 message1 of
    Left err -> do
      debugError $ "Handshake failed: " ++ show err
      return ()

    Right (responderState1, remoteStatic, decryptedTimestamp) -> do
      debugSuccess "Message 1 successfully decrypted!"
      debugHex "Recovered Initiator Static Key" (publicKeyToBytes remoteStatic)
      debugHex "Recovered Timestamp" decryptedTimestamp

      -- Verify keys match
      if publicKeyToBytes remoteStatic == publicKeyToBytes initiatorStaticPub
        then debugSuccess "Initiator identity verified!"
        else debugError "SECURITY: Initiator identity mismatch!"

      separator

      -- Step 6: Message 2 (Responder -> Initiator)
      debugStep 6 "Message 2: Responder -> Initiator"

      debugInfo "Message 2 contains:"
      debugInfo "  - Responder's ephemeral public key (32 bytes)"
      debugInfo "  - Encrypted empty payload (0 + 16 bytes)"
      debugInfo ""

      debugSubStep "Generating responder's ephemeral key..."
      responderEphemeral <- generatePrivateKey
      let responderEphemeralPub = derivePublicKey responderEphemeral
      debugHex "Responder Ephemeral Public Key" (publicKeyToBytes responderEphemeralPub)

      debugSubStep "Creating handshake message 2..."
      let (responderState2, message2, responderKeys) = responderWriteMessage responderState1 responderEphemeral

      debugHex "Message 2" message2
      debugKeyValue "Message 2 Length" (show (BS.length message2) ++ " bytes")
      debugKeyValue "Expected" "32 + 16 = 48 bytes"

      debugSubStep "Message 2 breakdown:"
      let (msg2Ephemeral, msg2EncEmpty) = BS.splitAt 32 message2
      debugHex "  [0:32]  Ephemeral Public Key" msg2Ephemeral
      debugHex "  [32:48] Encrypted Empty" msg2EncEmpty

      debugSuccess "Message 2 created"
      separator

      -- Step 7: Initiator Processes Message 2
      debugStep 7 "Initiator Processes Message 2"

      debugSubStep "Initiator reads and decrypts message 2..."
      case initiatorReadMessage initiatorState1 message2 of
        Left err -> do
          debugError $ "Handshake failed: " ++ show err
          return ()

        Right (initiatorState2, initiatorKeys) -> do
          debugSuccess "Message 2 successfully decrypted!"
          debugSuccess "Handshake complete!"
          separator

          -- Step 8: Session Keys
          debugStep 8 "Derived Session Keys"

          debugInfo "Both parties now have identical session keys"
          debugInfo "for encrypting transport data."
          debugInfo ""

          debugSubStep "Initiator's session keys:"
          debugHex "  Send Key" (symmetricKeyToBytes $ csKey $ skSend initiatorKeys)
          debugHex "  Recv Key" (symmetricKeyToBytes $ csKey $ skReceive initiatorKeys)

          debugSubStep "Responder's session keys:"
          debugHex "  Send Key" (symmetricKeyToBytes $ csKey $ skSend responderKeys)
          debugHex "  Recv Key" (symmetricKeyToBytes $ csKey $ skReceive responderKeys)

          -- Verify keys match (send/recv are swapped between parties)
          let initSend = symmetricKeyToBytes $ csKey $ skSend initiatorKeys
              respRecv = symmetricKeyToBytes $ csKey $ skReceive responderKeys
              initRecv = symmetricKeyToBytes $ csKey $ skReceive initiatorKeys
              respSend = symmetricKeyToBytes $ csKey $ skSend responderKeys

          if initSend == respRecv && initRecv == respSend
            then debugSuccess "Session keys verified! Parties can now communicate securely."
            else debugError "SECURITY: Session key mismatch!"

          separator

          -- Step 9: Demonstrate Transport Encryption
          debugStep 9 "Transport Data Encryption"

          let testMessage = "Hello from initiator!"
          debugKeyValue "Original Message" testMessage

          -- Encrypt with initiator's send key
          let sendNonce = nonceFromCounter (csNonce $ skSend initiatorKeys)
              ciphertext = encrypt
                (csKey $ skSend initiatorKeys)
                sendNonce
                BS.empty  -- No AAD in transport
                (BS.pack $ map (fromIntegral . fromEnum) testMessage)

          debugHex "Encrypted" ciphertext

          -- Decrypt with responder's receive key
          let recvNonce = nonceFromCounter (csNonce $ skReceive responderKeys)
          case decrypt (csKey $ skReceive responderKeys) recvNonce BS.empty ciphertext of
            Nothing -> debugError "Transport decryption failed!"
            Just plaintext -> do
              let decrypted = map (toEnum . fromIntegral) $ BS.unpack plaintext
              debugKeyValue "Decrypted" decrypted
              debugSuccess "Transport encryption working correctly!"

          separator

          -- Summary
          debugSection "Handshake Summary"

          boxed "Noise_IKpsk2 Handshake Complete"
            [ "✓ Mutual authentication achieved"
            , "✓ Forward secrecy (ephemeral keys)"
            , "✓ Identity hiding (initiator encrypted)"
            , "✓ PSK mixed in (post-quantum protection)"
            , "✓ Session keys derived"
            ]

          debugTable
            [ ("Messages Exchanged", "2")
            , ("Message 1 Size", "108 bytes")
            , ("Message 2 Size", "48 bytes")
            , ("Total Handshake", "156 bytes")
            , ("Session Keys", "2 × 32 bytes")
            ]

          debugSuccess "Noise handshake example completed!"


-- | Create a TAI64N timestamp (12 bytes)
createTimestamp :: IO BS.ByteString
createTimestamp = do
  now <- getPOSIXTime
  let secs = floor now :: Word64
      nsecs = floor ((now - fromIntegral secs) * 1e9) :: Word64
      -- TAI64N format: 8 bytes seconds + 4 bytes nanoseconds
      -- Add 2^62 for TAI64 epoch
      tai64 = secs + 0x400000000000000a
  pure $ BS.pack $
    [ fromIntegral ((tai64 `div` (256^7)) `mod` 256)
    , fromIntegral ((tai64 `div` (256^6)) `mod` 256)
    , fromIntegral ((tai64 `div` (256^5)) `mod` 256)
    , fromIntegral ((tai64 `div` (256^4)) `mod` 256)
    , fromIntegral ((tai64 `div` (256^3)) `mod` 256)
    , fromIntegral ((tai64 `div` (256^2)) `mod` 256)
    , fromIntegral ((tai64 `div` 256) `mod` 256)
    , fromIntegral (tai64 `mod` 256)
    , fromIntegral ((nsecs `div` (256^3)) `mod` 256)
    , fromIntegral ((nsecs `div` (256^2)) `mod` 256)
    , fromIntegral ((nsecs `div` 256) `mod` 256)
    , fromIntegral (nsecs `mod` 256)
    ]
