{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- |
-- Module      : Tailscale.TSNet
-- Description : Embedded Tailscale server (tsnet)
-- License     : BSD-3-Clause
--
-- This module provides an embedded Tailscale server that allows your Haskell
-- application to appear as a node on a Tailscale network. This is a port of
-- the Go tsnet package.
--
-- = Prerequisites
--
-- You must build the tsnet shared library before using this module:
--
-- @
-- cd go
-- go mod tidy
-- go build -buildmode=c-shared -o ..\/libtsnet.so tsnet_ffi.go
-- @
--
-- Then link your Haskell program against libtsnet.so.
--
-- = Example: Simple HTTP Server
--
-- @
-- {-# LANGUAGE OverloadedStrings #-}
-- import Tailscale.TSNet
-- import Network.Wai
-- import Network.Wai.Handler.Warp
-- import Network.HTTP.Types
--
-- main :: IO ()
-- main = do
--   -- Create and start the server
--   server <- newServer defaultServerConfig
--     { serverHostname = Just \"my-haskell-app\"
--     , serverAuthKey = Just \"tskey-auth-...\"  -- Or Nothing for interactive
--     }
--
--   result <- serverUp server
--   case result of
--     Left err -> error $ \"Failed to start: \" <> show err
--     Right () -> pure ()
--
--   -- Get our Tailscale IPs
--   (ipv4, ipv6) <- serverTailscaleIPs server
--   putStrLn $ \"IPv4: \" <> show ipv4
--   putStrLn $ \"IPv6: \" <> show ipv6
--
--   -- Listen for connections
--   listener <- serverListen server \"tcp\" \":8080\"
--   case listener of
--     Left err -> error $ \"Failed to listen: \" <> show err
--     Right ln -> do
--       putStrLn \"Listening on Tailscale...\"
--       -- Use with Warp or serve manually
--       serveWithListener ln app
--
-- app :: Application
-- app _ respond = respond $ responseLBS status200 [] \"Hello from Tailscale!\"
-- @
--
-- = Example: HTTPS with Automatic Certificates
--
-- @
-- main :: IO ()
-- main = do
--   server <- newServer defaultServerConfig
--     { serverHostname = Just \"secure-app\" }
--
--   _ <- serverUp server
--
--   -- ListenTLS automatically provisions HTTPS certificates
--   listener <- serverListenTLS server \"tcp\" \":443\"
--   case listener of
--     Left err -> error $ show err
--     Right ln -> serveWithListener ln app
-- @
--
-- = Example: Expose to Public Internet (Funnel)
--
-- @
-- main :: IO ()
-- main = do
--   server <- newServer defaultServerConfig
--     { serverHostname = Just \"public-app\" }
--
--   _ <- serverUp server
--
--   -- Funnel exposes your service to the public internet
--   listener <- serverListenFunnel server \"tcp\" \":443\" False
--   case listener of
--     Left err -> error $ show err
--     Right ln -> do
--       putStrLn \"Available at https:\/\/public-app.your-tailnet.ts.net\"
--       serveWithListener ln app
-- @
module Tailscale.TSNet
  ( -- * Server
    Server
  , ServerConfig (..)
  , defaultServerConfig
  , newServer
  , serverStart
  , serverUp
  , serverClose
  , withServer

    -- * Server Information
  , serverTailscaleIPs
  , serverCertDomains

    -- * Listening
  , Listener
  , serverListen
  , serverListenTLS
  , serverListenFunnel
  , listenerAccept
  , listenerAddr
  , listenerClose
  , withListener

    -- * Connections
  , Connection
  , serverDial
  , connRead
  , connWrite
  , connRemoteAddr
  , connLocalAddr
  , connClose
  , withConnection

    -- * Errors
  , TSNetError (..)
  ) where

import Control.Exception (bracket, bracketOnError)
import Control.Monad (when)
import Data.Text (Text)
import qualified Data.Text as T
import Foreign
import Foreign.C.String

import Tailscale.TSNet.FFI

-- | Errors from tsnet operations
data TSNetError
  = TSNetStartError !Text
  | TSNetListenError !Text
  | TSNetDialError !Text
  | TSNetAcceptError !Text
  | TSNetReadError !Text
  | TSNetWriteError !Text
  | TSNetCloseError !Text
  | TSNetEOF
  deriving (Eq, Show)

-- | Configuration for a tsnet server
data ServerConfig = ServerConfig
  { serverHostname  :: !(Maybe Text)
    -- ^ Hostname for this node on the tailnet
  , serverAuthKey   :: !(Maybe Text)
    -- ^ Auth key for automatic registration (or Nothing for interactive)
  , serverEphemeral :: !Bool
    -- ^ Whether to register as an ephemeral node (auto-deleted when offline)
  , serverStateDir  :: !(Maybe FilePath)
    -- ^ Directory for state storage (or Nothing for default)
  }
  deriving (Eq, Show)

-- | Default server configuration
defaultServerConfig :: ServerConfig
defaultServerConfig = ServerConfig
  { serverHostname = Nothing
  , serverAuthKey = Nothing
  , serverEphemeral = False
  , serverStateDir = Nothing
  }

-- | A tsnet server handle
newtype Server = Server { serverID :: ServerID }
  deriving (Eq, Show)

-- | A tsnet listener handle
newtype Listener = Listener { listenerID :: ListenerID }
  deriving (Eq, Show)

-- | A tsnet connection handle
newtype Connection = Connection { connID :: ConnID }
  deriving (Eq, Show)

-- | Helper to check result and extract error
checkResult :: TSNetResult -> IO (Either Text ())
checkResult (TSNetResult success errPtr)
  | success == 1 = pure $ Right ()
  | success == 2 = pure $ Left "EOF"
  | otherwise = do
      err <- if errPtr == nullPtr
        then pure "unknown error"
        else do
          e <- peekCString errPtr
          c_tsnet_free_string errPtr
          pure $ T.pack e
      pure $ Left err

-- | Create a new tsnet server
--
-- The server is not started yet; call 'serverStart' or 'serverUp'.
newServer :: ServerConfig -> IO Server
newServer ServerConfig{..} = do
  hostname <- maybe (pure nullPtr) newCString (T.unpack <$> serverHostname)
  authKey <- maybe (pure nullPtr) newCString (T.unpack <$> serverAuthKey)
  stateDir <- maybe (pure nullPtr) newCString serverStateDir
  let ephemeral = if serverEphemeral then 1 else 0

  sid <- c_tsnet_server_new hostname authKey ephemeral stateDir

  -- Free temporary strings
  when (hostname /= nullPtr) $ free hostname
  when (authKey /= nullPtr) $ free authKey
  when (stateDir /= nullPtr) $ free stateDir

  pure $ Server (ServerID sid)

-- | Start the server (connect to tailnet)
--
-- This returns immediately after initiating the connection.
-- Use 'serverUp' if you want to wait until fully connected.
serverStart :: Server -> IO (Either TSNetError ())
serverStart (Server (ServerID sid)) = do
  result <- c_tsnet_server_start sid
  res <- checkResult result
  pure $ case res of
    Left err -> Left $ TSNetStartError err
    Right () -> Right ()

-- | Start the server and wait until connected
--
-- This blocks until the server is fully connected to the tailnet.
serverUp :: Server -> IO (Either TSNetError ())
serverUp (Server (ServerID sid)) = do
  result <- c_tsnet_server_up sid
  res <- checkResult result
  pure $ case res of
    Left err -> Left $ TSNetStartError err
    Right () -> Right ()

-- | Close the server
serverClose :: Server -> IO (Either TSNetError ())
serverClose (Server (ServerID sid)) = do
  result <- c_tsnet_server_close sid
  res <- checkResult result
  pure $ case res of
    Left err -> Left $ TSNetCloseError err
    Right () -> Right ()

-- | Run an action with a server, ensuring it's closed afterward
withServer :: ServerConfig -> (Server -> IO a) -> IO a
withServer config = bracket
  (do
    server <- newServer config
    _ <- serverUp server
    pure server)
  (\server -> serverClose server >> pure ())

-- | Get the Tailscale IP addresses for this server
serverTailscaleIPs :: Server -> IO (Maybe Text, Maybe Text)
serverTailscaleIPs (Server (ServerID sid)) = do
  TSNetIPs ip4Ptr ip6Ptr <- c_tsnet_server_tailscale_ips sid
  ip4 <- if ip4Ptr == nullPtr
    then pure Nothing
    else do
      s <- peekCString ip4Ptr
      c_tsnet_free_string ip4Ptr
      pure $ Just $ T.pack s
  ip6 <- if ip6Ptr == nullPtr
    then pure Nothing
    else do
      s <- peekCString ip6Ptr
      c_tsnet_free_string ip6Ptr
      pure $ Just $ T.pack s
  pure (ip4, ip6)

-- | Get the certificate domains for this server
serverCertDomains :: Server -> IO [Text]
serverCertDomains (Server (ServerID sid)) = do
  alloca $ \lenPtr -> do
    arrPtr <- c_tsnet_server_cert_domains sid lenPtr
    len <- peek lenPtr
    if arrPtr == nullPtr || len == 0
      then pure []
      else do
        arr <- peekArray (fromIntegral len) arrPtr
        domains <- mapM (\cstr -> T.pack <$> peekCString cstr) arr
        c_tsnet_free_string_array arrPtr len
        pure domains

-- | Listen for connections on the tailnet
--
-- @
-- listener <- serverListen server \"tcp\" \":8080\"
-- @
serverListen :: Server -> Text -> Text -> IO (Either TSNetError Listener)
serverListen (Server (ServerID sid)) network addr = do
  networkC <- newCString (T.unpack network)
  addrC <- newCString (T.unpack addr)
  alloca $ \resultPtr -> do
    lid <- c_tsnet_server_listen sid networkC addrC resultPtr
    free networkC
    free addrC
    result <- peek resultPtr
    res <- checkResult result
    pure $ case res of
      Left err -> Left $ TSNetListenError err
      Right () -> Right $ Listener (ListenerID lid)

-- | Listen with automatic TLS certificate provisioning
--
-- Tailscale will automatically provision and renew HTTPS certificates.
--
-- @
-- listener <- serverListenTLS server \"tcp\" \":443\"
-- @
serverListenTLS :: Server -> Text -> Text -> IO (Either TSNetError Listener)
serverListenTLS (Server (ServerID sid)) network addr = do
  networkC <- newCString (T.unpack network)
  addrC <- newCString (T.unpack addr)
  alloca $ \resultPtr -> do
    lid <- c_tsnet_server_listen_tls sid networkC addrC resultPtr
    free networkC
    free addrC
    result <- peek resultPtr
    res <- checkResult result
    pure $ case res of
      Left err -> Left $ TSNetListenError err
      Right () -> Right $ Listener (ListenerID lid)

-- | Listen via Tailscale Funnel (expose to public internet)
--
-- Funnel allows your service to be accessible from the public internet
-- without port forwarding. Only TCP on ports 443, 8443, and 10000 is supported.
--
-- @
-- listener <- serverListenFunnel server \"tcp\" \":443\" False
-- @
serverListenFunnel
  :: Server
  -> Text    -- ^ Network (must be "tcp")
  -> Text    -- ^ Address (port must be 443, 8443, or 10000)
  -> Bool    -- ^ Funnel-only (reject tailnet connections)
  -> IO (Either TSNetError Listener)
serverListenFunnel (Server (ServerID sid)) network addr funnelOnly = do
  networkC <- newCString (T.unpack network)
  addrC <- newCString (T.unpack addr)
  let funnelOnlyC = if funnelOnly then 1 else 0
  alloca $ \resultPtr -> do
    lid <- c_tsnet_server_listen_funnel sid networkC addrC funnelOnlyC resultPtr
    free networkC
    free addrC
    result <- peek resultPtr
    res <- checkResult result
    pure $ case res of
      Left err -> Left $ TSNetListenError err
      Right () -> Right $ Listener (ListenerID lid)

-- | Accept a connection from a listener
listenerAccept :: Listener -> IO (Either TSNetError Connection)
listenerAccept (Listener (ListenerID lid)) = do
  alloca $ \resultPtr -> do
    cid <- c_tsnet_listener_accept lid resultPtr
    result <- peek resultPtr
    res <- checkResult result
    pure $ case res of
      Left err -> Left $ TSNetAcceptError err
      Right () -> Right $ Connection (ConnID cid)

-- | Get the address the listener is bound to
listenerAddr :: Listener -> IO (Text, Text)
listenerAddr (Listener (ListenerID lid)) = do
  TSNetListenerAddr netPtr addrPtr <- c_tsnet_listener_addr lid
  network <- if netPtr == nullPtr
    then pure ""
    else do
      s <- peekCString netPtr
      c_tsnet_free_string netPtr
      pure $ T.pack s
  addr <- if addrPtr == nullPtr
    then pure ""
    else do
      s <- peekCString addrPtr
      c_tsnet_free_string addrPtr
      pure $ T.pack s
  pure (network, addr)

-- | Close a listener
listenerClose :: Listener -> IO (Either TSNetError ())
listenerClose (Listener (ListenerID lid)) = do
  result <- c_tsnet_listener_close lid
  res <- checkResult result
  pure $ case res of
    Left err -> Left $ TSNetCloseError err
    Right () -> Right ()

-- | Run an action with a listener, ensuring it's closed afterward
withListener
  :: Server
  -> Text
  -> Text
  -> (Listener -> IO a)
  -> IO (Either TSNetError a)
withListener server network addr action = do
  listenerResult <- serverListen server network addr
  case listenerResult of
    Left err -> pure $ Left err
    Right listener -> do
      result <- action listener `finally` listenerClose listener
      pure $ Right result
  where
    finally a b = do
      r <- a
      _ <- b
      pure r

-- | Dial an outbound connection over the tailnet
--
-- @
-- conn <- serverDial server \"tcp\" \"other-host:22\"
-- @
serverDial :: Server -> Text -> Text -> IO (Either TSNetError Connection)
serverDial (Server (ServerID sid)) network address = do
  networkC <- newCString (T.unpack network)
  addressC <- newCString (T.unpack address)
  alloca $ \resultPtr -> do
    cid <- c_tsnet_server_dial sid networkC addressC resultPtr
    free networkC
    free addressC
    result <- peek resultPtr
    res <- checkResult result
    pure $ case res of
      Left err -> Left $ TSNetDialError err
      Right () -> Right $ Connection (ConnID cid)

-- | Read from a connection
connRead :: Connection -> Int -> IO (Either TSNetError (Int, Ptr Word8))
connRead (Connection (ConnID cid)) bufLen = do
  buf <- mallocArray bufLen
  alloca $ \resultPtr -> do
    n <- c_tsnet_conn_read cid (castPtr buf) (fromIntegral bufLen) resultPtr
    result <- peek resultPtr
    let success = tsnetResultSuccess result
    if success == 2
      then do
        free buf
        pure $ Left TSNetEOF
      else if success == 1
        then pure $ Right (fromIntegral n, buf)
        else do
          err <- if tsnetResultError result == nullPtr
            then pure "read error"
            else do
              e <- peekCString (tsnetResultError result)
              c_tsnet_free_string (tsnetResultError result)
              pure $ T.pack e
          free buf
          pure $ Left $ TSNetReadError err

-- | Write to a connection
connWrite :: Connection -> Ptr Word8 -> Int -> IO (Either TSNetError Int)
connWrite (Connection (ConnID cid)) buf len = do
  alloca $ \resultPtr -> do
    n <- c_tsnet_conn_write cid (castPtr buf) (fromIntegral len) resultPtr
    result <- peek resultPtr
    res <- checkResult result
    pure $ case res of
      Left err -> Left $ TSNetWriteError err
      Right () -> Right $ fromIntegral n

-- | Get the remote address of a connection
connRemoteAddr :: Connection -> IO (Maybe Text)
connRemoteAddr (Connection (ConnID cid)) = do
  ptr <- c_tsnet_conn_remote_addr cid
  if ptr == nullPtr
    then pure Nothing
    else do
      s <- peekCString ptr
      c_tsnet_free_string ptr
      pure $ Just $ T.pack s

-- | Get the local address of a connection
connLocalAddr :: Connection -> IO (Maybe Text)
connLocalAddr (Connection (ConnID cid)) = do
  ptr <- c_tsnet_conn_local_addr cid
  if ptr == nullPtr
    then pure Nothing
    else do
      s <- peekCString ptr
      c_tsnet_free_string ptr
      pure $ Just $ T.pack s

-- | Close a connection
connClose :: Connection -> IO (Either TSNetError ())
connClose (Connection (ConnID cid)) = do
  result <- c_tsnet_conn_close cid
  res <- checkResult result
  pure $ case res of
    Left err -> Left $ TSNetCloseError err
    Right () -> Right ()

-- | Run an action with a connection, ensuring it's closed afterward
withConnection :: IO (Either TSNetError Connection) -> (Connection -> IO a) -> IO (Either TSNetError a)
withConnection mkConn action = do
  connResult <- mkConn
  case connResult of
    Left err -> pure $ Left err
    Right conn -> do
      result <- action conn `finally` connClose conn
      pure $ Right result
  where
    finally a b = do
      r <- a
      _ <- b
      pure r
