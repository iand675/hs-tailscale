{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Tailscale.TSNet.FFI
-- Description : Low-level FFI bindings to tsnet
-- License     : BSD-3-Clause
--
-- This module provides low-level FFI bindings to the tsnet Go library.
-- Most users should use "Tailscale.TSNet" instead, which provides a
-- higher-level interface.
--
-- = Building the tsnet Library
--
-- Before using this module, you must build the tsnet shared library:
--
-- @
-- cd go
-- go build -buildmode=c-shared -o ..\/libtsnet.so tsnet_ffi.go
-- @
--
-- Then link against it when building your Haskell project.
module Tailscale.TSNet.FFI
  ( -- * Handle Types
    ServerID (..)
  , ListenerID (..)
  , ConnID (..)

    -- * Result Types
  , TSNetResult (..)
  , TSNetIPs (..)
  , TSNetListenerAddr (..)

    -- * Server Functions
  , c_tsnet_server_new
  , c_tsnet_server_start
  , c_tsnet_server_up
  , c_tsnet_server_close
  , c_tsnet_server_tailscale_ips
  , c_tsnet_server_cert_domains
  , c_tsnet_server_listen
  , c_tsnet_server_listen_tls
  , c_tsnet_server_listen_funnel
  , c_tsnet_server_dial

    -- * Listener Functions
  , c_tsnet_listener_accept
  , c_tsnet_listener_addr
  , c_tsnet_listener_close

    -- * Connection Functions
  , c_tsnet_conn_read
  , c_tsnet_conn_write
  , c_tsnet_conn_remote_addr
  , c_tsnet_conn_local_addr
  , c_tsnet_conn_close

    -- * Memory Management
  , c_tsnet_free_string
  , c_tsnet_free_string_array
  ) where

import Foreign
import Foreign.C.String
import Foreign.C.Types

-- | Handle to a tsnet server
newtype ServerID = ServerID Word64
  deriving (Eq, Show, Storable)

-- | Handle to a tsnet listener
newtype ListenerID = ListenerID Word64
  deriving (Eq, Show, Storable)

-- | Handle to a tsnet connection
newtype ConnID = ConnID Word64
  deriving (Eq, Show, Storable)

-- | Result from a tsnet operation
data TSNetResult = TSNetResult
  { tsnetResultSuccess :: !CInt
    -- ^ 0 = error, 1 = success, 2 = EOF
  , tsnetResultError   :: !CString
    -- ^ Error message (must be freed with c_tsnet_free_string)
  }

instance Storable TSNetResult where
  sizeOf _ = sizeOf (undefined :: CInt) + sizeOf (undefined :: CString)
  alignment _ = alignment (undefined :: CString)
  peek ptr = do
    success <- peekByteOff ptr 0
    err <- peekByteOff ptr (sizeOf (undefined :: CInt))
    return $ TSNetResult success err
  poke ptr (TSNetResult success err) = do
    pokeByteOff ptr 0 success
    pokeByteOff ptr (sizeOf (undefined :: CInt)) err

-- | Tailscale IP addresses
data TSNetIPs = TSNetIPs
  { tsnetIPv4 :: !CString
  , tsnetIPv6 :: !CString
  }

instance Storable TSNetIPs where
  sizeOf _ = 2 * sizeOf (undefined :: CString)
  alignment _ = alignment (undefined :: CString)
  peek ptr = do
    ip4 <- peekByteOff ptr 0
    ip6 <- peekByteOff ptr (sizeOf (undefined :: CString))
    return $ TSNetIPs ip4 ip6
  poke ptr (TSNetIPs ip4 ip6) = do
    pokeByteOff ptr 0 ip4
    pokeByteOff ptr (sizeOf (undefined :: CString)) ip6

-- | Listener address information
data TSNetListenerAddr = TSNetListenerAddr
  { tsnetListenerNetwork :: !CString
  , tsnetListenerAddr    :: !CString
  }

instance Storable TSNetListenerAddr where
  sizeOf _ = 2 * sizeOf (undefined :: CString)
  alignment _ = alignment (undefined :: CString)
  peek ptr = do
    net <- peekByteOff ptr 0
    addr <- peekByteOff ptr (sizeOf (undefined :: CString))
    return $ TSNetListenerAddr net addr
  poke ptr (TSNetListenerAddr net addr) = do
    pokeByteOff ptr 0 net
    pokeByteOff ptr (sizeOf (undefined :: CString)) addr

--------------------------------------------------------------------------------
-- Server Functions
--------------------------------------------------------------------------------

foreign import ccall safe "tsnet_server_new"
  c_tsnet_server_new
    :: CString    -- ^ hostname
    -> CString    -- ^ authKey
    -> CInt       -- ^ ephemeral
    -> CString    -- ^ stateDir
    -> IO Word64

foreign import ccall safe "tsnet_server_start"
  c_tsnet_server_start :: Word64 -> IO TSNetResult

foreign import ccall safe "tsnet_server_up"
  c_tsnet_server_up :: Word64 -> IO TSNetResult

foreign import ccall safe "tsnet_server_close"
  c_tsnet_server_close :: Word64 -> IO TSNetResult

foreign import ccall safe "tsnet_server_tailscale_ips"
  c_tsnet_server_tailscale_ips :: Word64 -> IO TSNetIPs

foreign import ccall safe "tsnet_server_cert_domains"
  c_tsnet_server_cert_domains
    :: Word64       -- ^ serverID
    -> Ptr CInt     -- ^ outLen
    -> IO (Ptr CString)

foreign import ccall safe "tsnet_server_listen"
  c_tsnet_server_listen
    :: Word64       -- ^ serverID
    -> CString      -- ^ network
    -> CString      -- ^ addr
    -> Ptr TSNetResult  -- ^ result (out)
    -> IO Word64

foreign import ccall safe "tsnet_server_listen_tls"
  c_tsnet_server_listen_tls
    :: Word64
    -> CString
    -> CString
    -> Ptr TSNetResult
    -> IO Word64

foreign import ccall safe "tsnet_server_listen_funnel"
  c_tsnet_server_listen_funnel
    :: Word64
    -> CString
    -> CString
    -> CInt         -- ^ funnelOnly
    -> Ptr TSNetResult
    -> IO Word64

foreign import ccall safe "tsnet_server_dial"
  c_tsnet_server_dial
    :: Word64
    -> CString      -- ^ network
    -> CString      -- ^ address
    -> Ptr TSNetResult
    -> IO Word64

--------------------------------------------------------------------------------
-- Listener Functions
--------------------------------------------------------------------------------

foreign import ccall safe "tsnet_listener_accept"
  c_tsnet_listener_accept
    :: Word64           -- ^ listenerID
    -> Ptr TSNetResult  -- ^ result (out)
    -> IO Word64

foreign import ccall safe "tsnet_listener_addr"
  c_tsnet_listener_addr :: Word64 -> IO TSNetListenerAddr

foreign import ccall safe "tsnet_listener_close"
  c_tsnet_listener_close :: Word64 -> IO TSNetResult

--------------------------------------------------------------------------------
-- Connection Functions
--------------------------------------------------------------------------------

foreign import ccall safe "tsnet_conn_read"
  c_tsnet_conn_read
    :: Word64           -- ^ connID
    -> Ptr CChar        -- ^ buf
    -> CInt             -- ^ bufLen
    -> Ptr TSNetResult  -- ^ result (out)
    -> IO CInt

foreign import ccall safe "tsnet_conn_write"
  c_tsnet_conn_write
    :: Word64
    -> Ptr CChar
    -> CInt
    -> Ptr TSNetResult
    -> IO CInt

foreign import ccall safe "tsnet_conn_remote_addr"
  c_tsnet_conn_remote_addr :: Word64 -> IO CString

foreign import ccall safe "tsnet_conn_local_addr"
  c_tsnet_conn_local_addr :: Word64 -> IO CString

foreign import ccall safe "tsnet_conn_close"
  c_tsnet_conn_close :: Word64 -> IO TSNetResult

--------------------------------------------------------------------------------
-- Memory Management
--------------------------------------------------------------------------------

foreign import ccall safe "tsnet_free_string"
  c_tsnet_free_string :: CString -> IO ()

foreign import ccall safe "tsnet_free_string_array"
  c_tsnet_free_string_array :: Ptr CString -> CInt -> IO ()
