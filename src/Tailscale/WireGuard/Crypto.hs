{- |
Module      : Tailscale.WireGuard.Crypto
Description : Re-export of WireGuard cryptographic primitives
License     : BSD-3-Clause

This module re-exports the WireGuard cryptographic primitives from the
wireguard package for backwards compatibility.
-}
module Tailscale.WireGuard.Crypto (
  module WireGuard.Crypto,
) where

import WireGuard.Crypto
