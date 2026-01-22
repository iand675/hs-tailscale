{-# LANGUAGE OverloadedStrings #-}

-- | Network listener for accepting connections on Tailscale network
module Network.Tailscale.Listener
  ( -- * Listener Types
    Listener(..)
  , ListenerConfig(..)
    -- * Listener Operations
  , newListener
  , listen
  , accept
  , closeListener
  , defaultListenerConfig
  ) where

import Control.Concurrent.STM (TVar, newTVarIO, readTVar, writeTVar, atomically)
import Control.Exception (bracket)
import Network.Socket (Socket, HostName, ServiceName)
import qualified Network.Socket as NS
import Network.Tailscale.Types
  ( Connection(..)
  , ConnectionState(..)
  , Endpoint(..)
  , Port(..)
  , Peer(..)
  , PeerID(..)
  , NodeKey(..)
  , PeerStatus(..)
  , TailscaleAddr(..)
  )
import Network.Tailscale.Client (Client)
import Data.Time (getCurrentTime)
import Data.Text (Text)

-- | Configuration for a listener
data ListenerConfig = ListenerConfig
  { listenerPort :: !Port
  , listenerBacklog :: !Int
  } deriving (Eq, Show)

-- | Default listener configuration
defaultListenerConfig :: Port -> ListenerConfig
defaultListenerConfig port = ListenerConfig
  { listenerPort = port
  , listenerBacklog = 128
  }

-- | A network listener on the Tailscale network
data Listener = Listener
  { listenerClient :: !Client
  , listenerConfig :: !ListenerConfig
  , listenerSocket :: !(TVar (Maybe Socket))
  , listenerActive :: !(TVar Bool)
  }

-- | Create a new listener
newListener :: Client -> ListenerConfig -> IO Listener
newListener client config = do
  socketVar <- newTVarIO Nothing
  activeVar <- newTVarIO False
  return $ Listener
    { listenerClient = client
    , listenerConfig = config
    , listenerSocket = socketVar
    , listenerActive = activeVar
    }

-- | Start listening for connections
listen :: Listener -> IO ()
listen listener = do
  let Port portNum = listenerPort (listenerConfig listener)
  
  -- Get address info for the port
  let hints = NS.defaultHints
        { NS.addrFlags = [NS.AI_PASSIVE]
        , NS.addrSocketType = NS.Stream
        }
  
  addr:_ <- NS.getAddrInfo (Just hints) Nothing (Just $ show portNum)
  
  -- Create and bind socket
  sock <- NS.socket (NS.addrFamily addr) (NS.addrSocketType addr) (NS.addrProtocol addr)
  NS.setSocketOption sock NS.ReuseAddr 1
  NS.bind sock (NS.addrAddress addr)
  NS.listen sock (listenerBacklog (listenerConfig listener))
  
  atomically $ do
    writeTVar (listenerSocket listener) (Just sock)
    writeTVar (listenerActive listener) True

-- | Accept an incoming connection
accept :: Listener -> IO Connection
accept listener = do
  mSocket <- atomically $ readTVar (listenerSocket listener)
  case mSocket of
    Nothing -> error "Listener not started"
    Just sock -> do
      (conn, addr) <- NS.accept sock
      now <- getCurrentTime
      
      -- In a real implementation, we would:
      -- 1. Extract peer information from the connection
      -- 2. Verify the peer is authorized
      -- 3. Set up encryption/authentication
      
      -- For now, create a dummy peer
      let dummyPeer = Peer
            { peerID = PeerID "peer-unknown"
            , peerNodeKey = NodeKey "unknown-key"
            , peerName = "Unknown Peer"
            , peerAddresses = []
            , peerStatus = PeerOnline
            , peerLastHandshake = Just now
            }
      
      let dummyEndpoint = Endpoint
            { endpointAddr = TailscaleIPv4 0  -- Placeholder
            , endpointPort = Port 0
            }
      
      return $ Connection
        { connPeer = dummyPeer
        , connLocalAddr = dummyEndpoint
        , connRemoteAddr = dummyEndpoint
        , connState = Connected
        , connEstablished = Just now
        }

-- | Close the listener
closeListener :: Listener -> IO ()
closeListener listener = do
  mSocket <- atomically $ do
    writeTVar (listenerActive listener) False
    readTVar (listenerSocket listener)
  
  case mSocket of
    Nothing -> return ()
    Just sock -> NS.close sock
  
  atomically $ writeTVar (listenerSocket listener) Nothing
