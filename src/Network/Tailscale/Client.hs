{-# LANGUAGE OverloadedStrings #-}

-- | Tailscale control plane client
module Network.Tailscale.Client
  ( -- * Client Types
    Client(..)
  , ClientError(..)
    -- * Client Operations
  , newClient
  , connectClient
  , disconnectClient
  , getStatus
    -- * Peer Operations
  , listPeers
  , getPeer
  ) where

import Control.Concurrent.STM (TVar, newTVarIO, readTVar, writeTVar, atomically)
import Control.Exception (Exception, throwIO)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (getCurrentTime)
import Network.Tailscale.Types
  ( Node(..)
  , NodeID(..)
  , NodeKey(..)
  , Peer(..)
  , PeerID(..)
  , PeerStatus(..)
  , AuthToken(..)
  , TailscaleAddr(..)
  , Endpoint(..)
  )
import Network.Tailscale.Config (Config(..))

-- | Errors that can occur during client operations
data ClientError
  = NotConnected
  | AuthenticationFailed Text
  | NetworkError Text
  | PeerNotFound PeerID
  deriving (Eq, Show)

instance Exception ClientError

-- | Tailscale client handle
data Client = Client
  { clientConfig :: !Config
  , clientNode :: !(TVar (Maybe Node))
  , clientPeers :: !(TVar [Peer])
  , clientConnected :: !(TVar Bool)
  }

-- | Create a new Tailscale client
newClient :: Config -> IO Client
newClient config = do
  nodeVar <- newTVarIO Nothing
  peersVar <- newTVarIO []
  connectedVar <- newTVarIO False
  return $ Client
    { clientConfig = config
    , clientNode = nodeVar
    , clientPeers = peersVar
    , clientConnected = connectedVar
    }

-- | Connect the client to the Tailscale network
connectClient :: Client -> AuthToken -> IO ()
connectClient client authToken = do
  -- In a real implementation, this would:
  -- 1. Establish connection to control plane
  -- 2. Perform authentication
  -- 3. Retrieve node information
  -- 4. Start background tasks for peer discovery
  
  now <- getCurrentTime
  
  -- Create a dummy node for demonstration
  let dummyNode = Node
        { nodeID = NodeID "node-123"
        , nodeKey = NodeKey "dummy-key"
        , nodeName = maybe "hs-tailscale-node" id (configHostname (clientConfig client))
        , nodeAddresses = []
        , nodeEndpoints = []
        , nodeCreated = now
        , nodeLastSeen = Just now
        }
  
  atomically $ do
    writeTVar (clientNode client) (Just dummyNode)
    writeTVar (clientConnected client) True

-- | Disconnect from the Tailscale network
disconnectClient :: Client -> IO ()
disconnectClient client = do
  atomically $ do
    writeTVar (clientNode client) Nothing
    writeTVar (clientConnected client) False
    writeTVar (clientPeers client) []

-- | Get current connection status
getStatus :: Client -> IO (Maybe Node)
getStatus client = atomically $ readTVar (clientNode client)

-- | List all peers in the network
listPeers :: Client -> IO [Peer]
listPeers client = do
  connected <- atomically $ readTVar (clientConnected client)
  if not connected
    then throwIO NotConnected
    else atomically $ readTVar (clientPeers client)

-- | Get information about a specific peer
getPeer :: Client -> PeerID -> IO (Maybe Peer)
getPeer client peerId = do
  peers <- listPeers client
  return $ findPeer peerId peers
  where
    findPeer :: PeerID -> [Peer] -> Maybe Peer
    findPeer pid = foldr (\p acc -> if peerID p == pid then Just p else acc) Nothing
