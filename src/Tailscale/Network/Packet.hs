{- |
Module      : Tailscale.Network.Packet
Description : Re-export of IP packet handling
License     : BSD-3-Clause

This module re-exports the IP packet handling from the
tsnet package for backwards compatibility.
-}
module Tailscale.Network.Packet (
  module Tsnet.Network.Packet,
) where

import Tsnet.Network.Packet
