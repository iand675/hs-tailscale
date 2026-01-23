{- |
Module      : Tailscale.ACL
Description : ACL management API
License     : BSD-3-Clause

This module re-exports ACL management functionality from @tailscale-api@.
-}
module Tailscale.ACL (
  getACL,
  getACLHuJSON,
  setACL,
  setACLHuJSON,
  previewACLForUser,
  previewACLForIPPort,
  previewACLHuJSONForUser,
  previewACLHuJSONForIPPort,
  validateACLJSON,
) where

import Tailscale.API.ACL
