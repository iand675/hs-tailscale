{- |
Module      : Tailscale.Control.Protocol
Description : Re-export of Tailscale control plane protocol
License     : BSD-3-Clause

This module re-exports the Tailscale control plane protocol from the
tsnet package for backwards compatibility.
-}
module Tailscale.Control.Protocol (
  module Tsnet.Control.Protocol,
) where

import Tsnet.Control.Protocol
