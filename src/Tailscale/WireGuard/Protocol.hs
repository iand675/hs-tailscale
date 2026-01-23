{- |
Module      : Tailscale.WireGuard.Protocol
Description : Re-export of WireGuard protocol implementation
License     : BSD-3-Clause

This module re-exports the WireGuard protocol implementation from the
wireguard package for backwards compatibility.
-}
module Tailscale.WireGuard.Protocol (
  module WireGuard.Protocol,
) where

import WireGuard.Protocol
