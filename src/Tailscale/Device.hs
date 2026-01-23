{- |
Module      : Tailscale.Device
Description : Device management API
License     : BSD-3-Clause

This module re-exports device management functionality from @tailscale-api@.
-}
module Tailscale.Device (
  getDevices,
  getDevice,
  deleteDevice,
  authorizeDevice,
  setAuthorized,
  setTags,
) where

import Tailscale.API.Device
