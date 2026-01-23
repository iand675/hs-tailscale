# wireguard

A pure Haskell implementation of the WireGuard protocol.

## Features

- **Pure Haskell** - No FFI or external dependencies beyond cryptographic libraries
- **Complete Protocol** - Implements the full WireGuard handshake and transport
- **Conformant** - Tested against WireGuard specification test vectors
- **Well-typed** - Strong type safety for keys, nonces, and protocol messages

## Cryptographic Primitives

| Operation | Algorithm | Library |
|-----------|-----------|---------|
| Key Exchange | Curve25519 ECDH | crypton |
| Symmetric Encryption | ChaCha20-Poly1305 | crypton |
| Hashing | BLAKE2s-256 | crypton |
| Key Derivation | HKDF-like (per WireGuard spec) | custom |

## Usage

```haskell
import WireGuard

main :: IO ()
main = do
  -- Generate key pairs
  alicePriv <- generatePrivateKey
  let alicePub = derivePublicKey alicePriv

  bobPriv <- generatePrivateKey
  let bobPub = derivePublicKey bobPriv

  -- Optional preshared key
  psk <- generatePresharedKey

  -- Alice initiates handshake to Bob
  let aliceHS = initiatorInit alicePriv bobPub (Just psk)
  aliceEph <- generatePrivateKey
  let timestamp = BS.replicate 12 0  -- TAI64N timestamp
  let (aliceHS', msg1) = initiatorWriteMessage aliceHS aliceEph timestamp

  -- Bob receives and responds
  let bobHS = responderInit bobPriv (Just psk)
  case responderReadMessage bobHS msg1 of
    Left err -> error $ show err
    Right (bobHS', remotePub, ts) -> do
      bobEph <- generatePrivateKey
      let (bobHS'', msg2, bobKeys) = responderWriteMessage bobHS' bobEph

      -- Alice completes handshake
      case initiatorReadMessage aliceHS' msg2 of
        Left err -> error $ show err
        Right (_, aliceKeys) -> do
          -- Now both have session keys for encrypted transport
          let encrypted = encryptTransport aliceKeys 0 "Hello, Bob!"
          case decryptTransport bobKeys 0 encrypted of
            Nothing -> error "Decryption failed"
            Just plaintext -> putStrLn $ "Bob received: " ++ show plaintext
```

## Protocol Overview

WireGuard uses the Noise_IKpsk2 handshake pattern:

```
<- s
...
-> e, es, s, ss
<- e, ee, se, psk
```

Where:
- `s` = static key pair
- `e` = ephemeral key pair
- `es` = DH(initiator_ephemeral, responder_static)
- `ss` = DH(initiator_static, responder_static)
- `ee` = DH(initiator_ephemeral, responder_ephemeral)
- `se` = DH(initiator_static, responder_ephemeral)
- `psk` = preshared key mixed after second message

## Testing

```bash
cabal test
```

The test suite includes:
- Cryptographic primitive tests
- WireGuard specification test vectors
- Noise protocol test vectors
- Full handshake integration tests
- Property-based tests

## References

- [WireGuard Protocol](https://www.wireguard.com/protocol/)
- [WireGuard Paper](https://www.wireguard.com/papers/wireguard.pdf)
- [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
- [Test Vectors](https://www.wireguard.com/protocol/#test-vectors)

## License

BSD-3-Clause
