{- |
Module      : Tailscale.Routes
Description : Route management API
License     : BSD-3-Clause

This module re-exports route management functionality from @tailscale-api@.
-}
module Tailscale.Routes (
  getRoutes,
  setRoutes,
) where

import Tailscale.API.Routes
