{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Core types for Tailscale networking
module Network.Tailscale.Types
  ( -- * Node Types
    Node(..)
  , NodeID(..)
  , NodeKey(..)
    -- * Peer Types
  , Peer(..)
  , PeerID(..)
  , PeerStatus(..)
    -- * Network Types
  , TailscaleAddr(..)
  , Endpoint(..)
  , Port(..)
    -- * Authentication Types
  , AuthKey(..)
  , DeviceKey(..)
  , AuthToken(..)
    -- * Connection Types
  , Connection(..)
  , ConnectionState(..)
  ) where

import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Time (UTCTime)
import GHC.Generics (Generic)
import Network.Socket (HostAddress, HostAddress6)

-- | Unique identifier for a Tailscale node
newtype NodeID = NodeID Text
  deriving (Eq, Ord, Show, Generic)

-- | Public key identifying a node
newtype NodeKey = NodeKey ByteString
  deriving (Eq, Ord, Show, Generic)

-- | Represents a Tailscale node
data Node = Node
  { nodeID :: !NodeID
  , nodeKey :: !NodeKey
  , nodeName :: !Text
  , nodeAddresses :: ![TailscaleAddr]
  , nodeEndpoints :: ![Endpoint]
  , nodeCreated :: !UTCTime
  , nodeLastSeen :: !(Maybe UTCTime)
  } deriving (Eq, Show, Generic)

-- | Unique identifier for a peer
newtype PeerID = PeerID Text
  deriving (Eq, Ord, Show, Generic)

-- | Status of a peer connection
data PeerStatus
  = PeerOnline
  | PeerOffline
  | PeerIdle
  deriving (Eq, Show, Generic)

-- | Represents a peer in the Tailscale network
data Peer = Peer
  { peerID :: !PeerID
  , peerNodeKey :: !NodeKey
  , peerName :: !Text
  , peerAddresses :: ![TailscaleAddr]
  , peerStatus :: !PeerStatus
  , peerLastHandshake :: !(Maybe UTCTime)
  } deriving (Eq, Show, Generic)

-- | Tailscale IP address (can be IPv4 or IPv6)
data TailscaleAddr
  = TailscaleIPv4 !HostAddress
  | TailscaleIPv6 !HostAddress6
  deriving (Eq, Show, Generic)

-- | Network port number
newtype Port = Port Int
  deriving (Eq, Ord, Show, Generic)

-- | Network endpoint (address + port)
data Endpoint = Endpoint
  { endpointAddr :: !TailscaleAddr
  , endpointPort :: !Port
  } deriving (Eq, Show, Generic)

-- | Authentication key for node registration
newtype AuthKey = AuthKey Text
  deriving (Eq, Show, Generic)

-- | Device-specific key for authentication
newtype DeviceKey = DeviceKey ByteString
  deriving (Eq, Show, Generic)

-- | Authentication token from control plane
newtype AuthToken = AuthToken Text
  deriving (Eq, Show, Generic)

-- | State of a network connection
data ConnectionState
  = Connecting
  | Connected
  | Disconnected
  | Failed Text
  deriving (Eq, Show, Generic)

-- | Represents an active connection
data Connection = Connection
  { connPeer :: !Peer
  , connLocalAddr :: !Endpoint
  , connRemoteAddr :: !Endpoint
  , connState :: !ConnectionState
  , connEstablished :: !(Maybe UTCTime)
  } deriving (Eq, Show, Generic)
