{- |
Module      : Tailscale.Tailnet
Description : Tailnet management API
License     : BSD-3-Clause

This module re-exports tailnet management functionality from @tailscale-api@.
-}
module Tailscale.Tailnet (
  deleteTailnet,
) where

import Tailscale.API.Tailnet
