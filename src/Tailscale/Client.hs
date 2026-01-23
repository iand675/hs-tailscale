{- |
Module      : Tailscale.Client
Description : HTTP client for the Tailscale API
License     : BSD-3-Clause

This module re-exports the HTTP client functionality from @tailscale-api@.
-}
module Tailscale.Client (
  -- * Client Types
  Client (..),
  AuthMethod (..),
  APIKey (..),

  -- * Client Construction
  newClient,
  defaultClient,

  -- * URL Building
  buildURL,
  buildTailnetURL,
  buildQueryString,
  urlEncodeText,

  -- * Request Execution
  doRequest,
  doRequestWithBody,
  sendRequest,

  -- * Response Handling
  handleErrorResponse,
  parseJsonResponse,

  -- * Constants
  defaultBaseURL,
  maxResponseSize,
) where

import Tailscale.API.Client
