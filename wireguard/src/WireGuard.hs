{- |
Module      : WireGuard
Description : Pure Haskell WireGuard protocol implementation
License     : BSD-3-Clause

This module provides a pure Haskell implementation of the WireGuard protocol,
including:

* Curve25519 ECDH key exchange
* ChaCha20-Poly1305 AEAD encryption
* BLAKE2s hashing and key derivation
* Noise_IKpsk2 handshake pattern
* WireGuard packet format parsing and serialization

= Overview

WireGuard is a modern VPN protocol that uses state-of-the-art cryptography:

* __Curve25519__ for Elliptic-Curve Diffie-Hellman (ECDH)
* __ChaCha20-Poly1305__ for authenticated encryption (AEAD)
* __BLAKE2s__ for hashing and key derivation
* __Noise Protocol Framework__ for the handshake

= Usage

== Key Generation

@
import WireGuard

main = do
  -- Generate key pairs
  privateKey <- generatePrivateKey
  let publicKey = derivePublicKey privateKey

  -- Optional: generate a preshared key for additional security
  psk <- generatePresharedKey
@

== Handshake (Initiator)

@
-- Initialize handshake as initiator (client)
let hsState = initiatorInit myPrivateKey serverPublicKey (Just psk)

-- Generate ephemeral key and create first message
ephemeral <- generatePrivateKey
let timestamp = ... -- 12-byte TAI64N timestamp
let (hsState', msg1) = initiatorWriteMessage hsState ephemeral timestamp

-- Send msg1, receive response msg2
-- ...

-- Process response
case initiatorReadMessage hsState' msg2 of
  Left err -> handleError err
  Right (finalState, sessionKeys) -> do
    -- Handshake complete, use sessionKeys for transport
@

== Transport Encryption

@
-- Encrypt data
let encrypted = encryptTransport sessionKeys counter plaintext

-- Decrypt data
case decryptTransport sessionKeys counter encrypted of
  Nothing -> handleDecryptionError
  Just plaintext -> processPacket plaintext
@

= Modules

* "WireGuard.Crypto" - Cryptographic primitives
* "WireGuard.Noise" - Noise_IK handshake protocol
* "WireGuard.Protocol" - WireGuard packet format and session management

= References

* [WireGuard Protocol](https://www.wireguard.com/protocol/)
* [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
* [WireGuard Paper](https://www.wireguard.com/papers/wireguard.pdf)
-}
module WireGuard (
  -- * Re-exports from WireGuard.Crypto
  module WireGuard.Crypto,

  -- * Re-exports from WireGuard.Noise
  module WireGuard.Noise,

  -- * Re-exports from WireGuard.Protocol
  module WireGuard.Protocol,
) where

import WireGuard.Crypto
import WireGuard.Noise
import WireGuard.Protocol
