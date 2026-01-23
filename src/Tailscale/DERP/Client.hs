{- |
Module      : Tailscale.DERP.Client
Description : Re-export of DERP client implementation
License     : BSD-3-Clause

This module re-exports the DERP client implementation from the
tsnet package for backwards compatibility.
-}
module Tailscale.DERP.Client (
  module Tsnet.DERP.Client,
) where

import Tsnet.DERP.Client
