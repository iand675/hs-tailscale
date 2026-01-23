{- |
Module      : Tailscale.Keys
Description : Auth key management API
License     : BSD-3-Clause

This module re-exports auth key management functionality from @tailscale-api@.
-}
module Tailscale.Keys (
  getKeys,
  getKey,
  createKey,
  createKeyWithExpiry,
  deleteKey,
  mkReusableKey,
  mkEphemeralKey,
  mkPreauthorizedKey,
) where

import Tailscale.API.Keys
