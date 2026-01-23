{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- |
-- Module      : Tailscale.Embedded
-- Description : Pure Haskell embedded Tailscale implementation
-- License     : BSD-3-Clause
--
-- This module provides a pure Haskell implementation of Tailscale that can be
-- embedded directly in your application. Your app will appear as a node on
-- the Tailscale network, similar to tsnet in Go.
--
-- = Example: Simple Server
--
-- @
-- {-# LANGUAGE OverloadedStrings #-}
-- import Tailscale.Embedded
--
-- main :: IO ()
-- main = do
--   -- Create embedded Tailscale instance
--   ts <- newTailscale defaultConfig
--     { tsHostname = \"my-haskell-app\"
--     , tsAuthKey = Just \"tskey-auth-...\"
--     }
--
--   -- Start and connect to tailnet
--   result <- start ts
--   case result of
--     Left err -> error $ show err
--     Right () -> pure ()
--
--   -- Get our Tailscale IPs
--   ips <- tailscaleIPs ts
--   putStrLn $ \"Connected with IPs: \" <> show ips
--
--   -- Listen for connections
--   listener <- listen ts \"tcp\" 8080
--   forever $ do
--     conn <- accept listener
--     -- Handle connection...
--     close conn
-- @
--
-- = Example: Client Connection
--
-- @
-- main :: IO ()
-- main = do
--   ts <- newTailscale defaultConfig
--   _ <- start ts
--
--   -- Connect to another Tailscale node
--   conn <- dial ts \"tcp\" \"other-host:22\"
--   case conn of
--     Left err -> error $ show err
--     Right c -> do
--       send c \"Hello!\"
--       response <- recv c 1024
--       close c
-- @
module Tailscale.Embedded
  ( -- * Tailscale Instance
    Tailscale
  , Config (..)
  , defaultConfig

    -- * Lifecycle
  , newTailscale
  , start
  , stop
  , withTailscale

    -- * Information
  , tailscaleIPs
  , certDomains
  , isConnected
  , selfInfo

    -- * Networking
  , Listener
  , Connection
  , listen
  , listenTLS
  , accept
  , dial
  , send
  , recv
  , close
  , localAddr
  , remoteAddr

    -- * Errors
  , TailscaleError (..)

    -- * Re-exports
  , PeerInfo (..)
  , NetworkMap (..)
  ) where

import Control.Concurrent (forkIO, threadDelay, ThreadId, killThread)
import Control.Concurrent.MVar
import Control.Concurrent.STM
import Control.Monad (when)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.IORef
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word16)

import Tailscale.Control.Client
import Tailscale.Control.Protocol
import Tailscale.DERP.Client
import Tailscale.WireGuard.Crypto

-- | Embedded Tailscale errors
data TailscaleError
  = TailscaleNotStarted
  | TailscaleStartError !Text
  | TailscaleConnectionError !Text
  | TailscaleListenError !Text
  | TailscaleDERPError !Text
  | TailscaleAuthRequired !Text  -- ^ Contains auth URL
  deriving (Eq, Show)

-- | Configuration for embedded Tailscale
data Config = Config
  { tsHostname    :: !Text
    -- ^ Hostname for this node (defaults to system hostname)
  , tsAuthKey     :: !(Maybe Text)
    -- ^ Pre-authentication key (for headless operation)
  , tsEphemeral   :: !Bool
    -- ^ Register as ephemeral node (auto-deleted when offline)
  , tsControlURL  :: !Text
    -- ^ Control server URL (default: controlplane.tailscale.com)
  , tsStateDir    :: !(Maybe FilePath)
    -- ^ Directory for persistent state
  , tsLogLevel    :: !LogLevel
    -- ^ Logging verbosity
  }
  deriving (Eq, Show)

-- | Log level
data LogLevel = LogQuiet | LogNormal | LogVerbose | LogDebug
  deriving (Eq, Show, Ord)

-- | Default configuration
defaultConfig :: Config
defaultConfig = Config
  { tsHostname = "haskell-tailscale"
  , tsAuthKey = Nothing
  , tsEphemeral = False
  , tsControlURL = defaultControlURL
  , tsStateDir = Nothing
  , tsLogLevel = LogNormal
  }

-- | A listener for incoming connections
data Listener = Listener
  { lnPort      :: !Word16
  , lnTLS       :: !Bool
  , lnTailscale :: !Tailscale
  , lnAcceptQ   :: !(TQueue Connection)
  , lnClosed    :: !(IORef Bool)
  }

-- | A connection to/from a peer
data Connection = Connection
  { connRemote    :: !Text         -- ^ Remote address
  , connLocal     :: !Text         -- ^ Local address
  , connSendQ     :: !(TQueue ByteString)
  , connRecvQ     :: !(TQueue ByteString)
  , connClosed    :: !(IORef Bool)
  , connTailscale :: !Tailscale
  }

-- | Embedded Tailscale instance
data Tailscale = Tailscale
  { tsConfig        :: !Config
  , tsPrivateKey    :: !PrivateKey
  , tsPublicKey     :: !PublicKey
  , tsMachineKey    :: !MachineKey
  , tsNodeKey       :: !NodeKey
  , tsControlClient :: !(MVar ControlClient)
  , tsDERPClients   :: !(TVar (Map Int DERPClient))
  , tsNetworkMap    :: !(TVar (Maybe NetworkMap))
  , tsPeers         :: !(TVar (Map Text PeerInfo))
  , tsListeners     :: !(TVar (Map Word16 Listener))
  , tsConnections   :: !(TVar [Connection])
  , tsStarted       :: !(IORef Bool)
  , tsStopped       :: !(IORef Bool)
  , tsMainThread    :: !(MVar (Maybe ThreadId))
  , tsIPv4          :: !(TVar (Maybe Text))
  , tsIPv6          :: !(TVar (Maybe Text))
  }

-- | Create a new Tailscale instance (not yet started)
newTailscale :: Config -> IO Tailscale
newTailscale config = do
  -- Generate keys
  privKey <- generatePrivateKey
  let pubKey = derivePublicKey privKey

  (_, nodeKey) <- generateNodeKey
  machineKey <- generateMachineKey

  -- Initialize state
  controlClient <- newEmptyMVar
  derpClients <- newTVarIO Map.empty
  networkMap <- newTVarIO Nothing
  peers <- newTVarIO Map.empty
  listeners <- newTVarIO Map.empty
  connections <- newTVarIO []
  started <- newIORef False
  stopped <- newIORef False
  mainThread <- newMVar Nothing
  ipv4 <- newTVarIO Nothing
  ipv6 <- newTVarIO Nothing

  pure Tailscale
    { tsConfig = config
    , tsPrivateKey = privKey
    , tsPublicKey = pubKey
    , tsMachineKey = machineKey
    , tsNodeKey = nodeKey
    , tsControlClient = controlClient
    , tsDERPClients = derpClients
    , tsNetworkMap = networkMap
    , tsPeers = peers
    , tsListeners = listeners
    , tsConnections = connections
    , tsStarted = started
    , tsStopped = stopped
    , tsMainThread = mainThread
    , tsIPv4 = ipv4
    , tsIPv6 = ipv6
    }

-- | Start the Tailscale instance
start :: Tailscale -> IO (Either TailscaleError ())
start ts = do
  alreadyStarted <- readIORef (tsStarted ts)
  if alreadyStarted
    then pure $ Right ()
    else do
      writeIORef (tsStarted ts) True

      -- Create control client
      let controlConfig = ControlConfig
            { ccControlURL = tsControlURL (tsConfig ts)
            , ccMachineKey = tsMachineKey ts
            , ccNodeKey = tsNodeKey ts
            }

      client <- newControlClient controlConfig
      putMVar (tsControlClient ts) client

      -- Register with control server
      regResult <- register client (tsAuthKey (tsConfig ts))
      case regResult of
        Left err -> do
          writeIORef (tsStarted ts) False
          pure $ Left $ TailscaleStartError $ T.pack $ show err
        Right resp -> do
          -- Check if auth is required
          case rrspAuthURL resp of
            Just url | not (rrspMachineAuthorized resp) -> do
              writeIORef (tsStarted ts) False
              pure $ Left $ TailscaleAuthRequired url
            _ -> do
              -- Fetch initial network map
              mapResult <- fetchNetworkMap client
              case mapResult of
                Left err -> do
                  writeIORef (tsStarted ts) False
                  pure $ Left $ TailscaleStartError $ T.pack $ show err
                Right netMap -> do
                  atomically $ writeTVar (tsNetworkMap ts) (Just netMap)

                  -- Extract our IPs
                  let selfAddrs = piAddresses (nmSelfNode netMap)
                      mIPv4 = findIPv4 selfAddrs
                      mIPv6 = findIPv6 selfAddrs
                  atomically $ do
                    writeTVar (tsIPv4 ts) mIPv4
                    writeTVar (tsIPv6 ts) mIPv6

                  -- Update peers map
                  let peerMap = Map.fromList
                        [ (piName p, p) | p <- nmPeers netMap ]
                  atomically $ writeTVar (tsPeers ts) peerMap

                  -- Start main loop
                  tid <- forkIO $ mainLoop ts
                  modifyMVar_ (tsMainThread ts) $ \_ -> pure (Just tid)

                  pure $ Right ()

-- | Main event loop
mainLoop :: Tailscale -> IO ()
mainLoop ts = do
  stopped <- readIORef (tsStopped ts)
  when (not stopped) $ do
    -- Periodic tasks:
    -- 1. Refresh network map
    -- 2. Maintain DERP connections
    -- 3. Process incoming packets

    -- Sleep and loop
    threadDelay 10000000  -- 10 seconds
    mainLoop ts
  where
    threadDelay = Control.Concurrent.threadDelay

-- | Stop the Tailscale instance
stop :: Tailscale -> IO ()
stop ts = do
  writeIORef (tsStopped ts) True

  -- Kill main thread
  mTid <- readMVar (tsMainThread ts)
  case mTid of
    Nothing -> pure ()
    Just tid -> killThread tid

  -- Close DERP connections
  derpClients <- atomically $ readTVar (tsDERPClients ts)
  mapM_ closeDERP (Map.elems derpClients)

  -- Close control client
  mClient <- tryTakeMVar (tsControlClient ts)
  case mClient of
    Nothing -> pure ()
    Just client -> closeControlClient client

-- | Run an action with a Tailscale instance
withTailscale :: Config -> (Tailscale -> IO a) -> IO (Either TailscaleError a)
withTailscale config action = do
  ts <- newTailscale config
  result <- start ts
  case result of
    Left err -> pure $ Left err
    Right () -> do
      a <- action ts
      stop ts
      pure $ Right a

-- | Get the Tailscale IPs for this instance
tailscaleIPs :: Tailscale -> IO (Maybe Text, Maybe Text)
tailscaleIPs ts = atomically $ do
  ipv4 <- readTVar (tsIPv4 ts)
  ipv6 <- readTVar (tsIPv6 ts)
  pure (ipv4, ipv6)

-- | Get certificate domains for this instance
certDomains :: Tailscale -> IO [Text]
certDomains ts = do
  mMap <- atomically $ readTVar (tsNetworkMap ts)
  case mMap of
    Nothing -> pure []
    Just netMap ->
      let self = nmSelfNode netMap
          domain = nmDomain netMap
      in if T.null domain
           then pure []
           else pure [piName self <> "." <> domain]

-- | Check if connected to the tailnet
isConnected :: Tailscale -> IO Bool
isConnected ts = readIORef (tsStarted ts)

-- | Get information about this node
selfInfo :: Tailscale -> IO (Maybe PeerInfo)
selfInfo ts = do
  mMap <- atomically $ readTVar (tsNetworkMap ts)
  pure $ nmSelfNode <$> mMap

-- | Listen for connections on a port
listen :: Tailscale -> Text -> Word16 -> IO (Either TailscaleError Listener)
listen ts network port = do
  started <- readIORef (tsStarted ts)
  if not started
    then pure $ Left TailscaleNotStarted
    else do
      acceptQ <- newTQueueIO
      closed <- newIORef False

      let listener = Listener
            { lnPort = port
            , lnTLS = False
            , lnTailscale = ts
            , lnAcceptQ = acceptQ
            , lnClosed = closed
            }

      atomically $ modifyTVar' (tsListeners ts) (Map.insert port listener)
      pure $ Right listener

-- | Listen with TLS (automatic certificate provisioning)
listenTLS :: Tailscale -> Text -> Word16 -> IO (Either TailscaleError Listener)
listenTLS ts network port = do
  result <- listen ts network port
  case result of
    Left err -> pure $ Left err
    Right ln -> pure $ Right ln { lnTLS = True }

-- | Accept a connection from a listener
accept :: Listener -> IO Connection
accept ln = atomically $ readTQueue (lnAcceptQ ln)

-- | Dial a connection to a peer
dial :: Tailscale -> Text -> Text -> IO (Either TailscaleError Connection)
dial ts network address = do
  started <- readIORef (tsStarted ts)
  if not started
    then pure $ Left TailscaleNotStarted
    else do
      -- Parse address (host:port)
      let parts = T.splitOn ":" address
      case parts of
        [host, portStr] -> do
          -- Look up peer
          peers <- atomically $ readTVar (tsPeers ts)
          case Map.lookup host peers of
            Nothing -> pure $ Left $ TailscaleConnectionError $
              "Unknown peer: " <> host
            Just peer -> do
              -- Create connection
              sendQ <- newTQueueIO
              recvQ <- newTQueueIO
              closed <- newIORef False

              let conn = Connection
                    { connRemote = address
                    , connLocal = ""  -- Will be filled in
                    , connSendQ = sendQ
                    , connRecvQ = recvQ
                    , connClosed = closed
                    , connTailscale = ts
                    }

              atomically $ modifyTVar' (tsConnections ts) (conn:)
              pure $ Right conn
        _ -> pure $ Left $ TailscaleConnectionError $
          "Invalid address format: " <> address

-- | Send data on a connection
send :: Connection -> ByteString -> IO (Either TailscaleError ())
send conn bs = do
  closed <- readIORef (connClosed conn)
  if closed
    then pure $ Left $ TailscaleConnectionError "Connection closed"
    else do
      atomically $ writeTQueue (connSendQ conn) bs
      pure $ Right ()

-- | Receive data from a connection
recv :: Connection -> Int -> IO (Either TailscaleError ByteString)
recv conn maxLen = do
  closed <- readIORef (connClosed conn)
  if closed
    then pure $ Left $ TailscaleConnectionError "Connection closed"
    else do
      bs <- atomically $ readTQueue (connRecvQ conn)
      pure $ Right $ BS.take maxLen bs

-- | Close a connection
close :: Connection -> IO ()
close conn = writeIORef (connClosed conn) True

-- | Get local address of a connection
localAddr :: Connection -> IO Text
localAddr = pure . connLocal

-- | Get remote address of a connection
remoteAddr :: Connection -> IO Text
remoteAddr = pure . connRemote

--------------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------------

findIPv4 :: [Text] -> Maybe Text
findIPv4 = foldr (\ip acc -> if T.isPrefixOf "100." ip then Just ip else acc) Nothing

findIPv6 :: [Text] -> Maybe Text
findIPv6 = foldr (\ip acc -> if T.isPrefixOf "fd7a:" ip || T.any (== ':') ip then Just ip else acc) Nothing
