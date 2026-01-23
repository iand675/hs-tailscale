{- |
Module      : Tailscale.DERP.Protocol
Description : Re-export of DERP protocol implementation
License     : BSD-3-Clause

This module re-exports the DERP protocol implementation from the
tsnet package for backwards compatibility.
-}
module Tailscale.DERP.Protocol (
  module Tsnet.DERP.Protocol,
) where

import Tsnet.DERP.Protocol
