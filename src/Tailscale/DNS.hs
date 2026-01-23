{- |
Module      : Tailscale.DNS
Description : DNS configuration API
License     : BSD-3-Clause

This module re-exports DNS configuration functionality from @tailscale-api@.
-}
module Tailscale.DNS (
  getDNSConfig,
  setDNSConfig,
  getNameServers,
  setNameServers,
  getDNSPreferences,
  setDNSPreferences,
  getSearchPaths,
  setSearchPaths,
) where

import Tailscale.API.DNS
