{- |
Module      : Tailscale.Control.Client
Description : Re-export of Tailscale control plane client
License     : BSD-3-Clause

This module re-exports the Tailscale control plane client from the
tsnet package for backwards compatibility.
-}
module Tailscale.Control.Client (
  module Tsnet.Control.Client,
) where

import Tsnet.Control.Client
