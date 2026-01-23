{- |
Module      : Tailscale.WireGuard.Noise
Description : Re-export of WireGuard Noise protocol implementation
License     : BSD-3-Clause

This module re-exports the WireGuard Noise protocol implementation from the
wireguard package for backwards compatibility.
-}
module Tailscale.WireGuard.Noise (
  module WireGuard.Noise,
) where

import WireGuard.Noise
