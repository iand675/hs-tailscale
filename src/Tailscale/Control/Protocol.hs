{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

{- |
Module      : Tailscale.Control.Protocol
Description : Tailscale control plane protocol
License     : BSD-3-Clause

This module implements communication with the Tailscale control plane
(coordination server). The control server:

* Authenticates nodes
* Distributes network maps (list of peers and their IPs)
* Coordinates key exchange
* Manages ACLs and policies

By default, this communicates with controlplane.tailscale.com, but
can be configured to use a self-hosted Headscale server.
-}
module Tailscale.Control.Protocol (
  -- * Types
  ControlConfig (..),
  NodeKey (..),
  MachineKey (..),
  NetworkMap (..),
  PeerInfo (..),
  DERPMap (..),
  DERPRegion (..),
  DERPNode (..),

  -- * Defaults
  defaultControlConfig,
  defaultControlURL,

  -- * Registration
  RegisterRequest (..),
  RegisterResponse (..),
  AuthInfo (..),

  -- * Map Requests
  MapRequest (..),
  MapResponse (..),
) where

import Data.Aeson
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as B64
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (UTCTime)
import Data.Word (Word16)
import GHC.Generics (Generic)

-- | Default control server URL
defaultControlURL :: Text
defaultControlURL = "https://controlplane.tailscale.com"

-- | Control plane configuration
data ControlConfig = ControlConfig
  { ccControlURL :: !Text
  -- ^ URL of the control server
  , ccMachineKey :: !MachineKey
  -- ^ This machine's key (persistent across reboots)
  , ccNodeKey :: !NodeKey
  -- ^ This node's key (may change on re-auth)
  }
  deriving (Eq, Show, Generic)

-- | Default control configuration
defaultControlConfig :: MachineKey -> NodeKey -> ControlConfig
defaultControlConfig mk nk =
  ControlConfig
    { ccControlURL = defaultControlURL
    , ccMachineKey = mk
    , ccNodeKey = nk
    }

-- | Node key (WireGuard public key for this node)
newtype NodeKey = NodeKey {unNodeKey :: ByteString}
  deriving (Eq, Show)

instance ToJSON NodeKey where
  toJSON (NodeKey k) = String $ "nodekey:" <> TE.decodeUtf8 (B64.encode k)

instance FromJSON NodeKey where
  parseJSON = withText "NodeKey" $ \t ->
    case T.stripPrefix "nodekey:" t of
      Nothing -> fail "Invalid node key format"
      Just b64 -> case B64.decode (TE.encodeUtf8 b64) of
        Left err -> fail err
        Right k -> pure $ NodeKey k

-- | Machine key (stable identifier for this machine)
newtype MachineKey = MachineKey {unMachineKey :: ByteString}
  deriving (Eq, Show)

instance ToJSON MachineKey where
  toJSON (MachineKey k) = String $ "mkey:" <> TE.decodeUtf8 (B64.encode k)

instance FromJSON MachineKey where
  parseJSON = withText "MachineKey" $ \t ->
    case T.stripPrefix "mkey:" t of
      Nothing -> fail "Invalid machine key format"
      Just b64 -> case B64.decode (TE.encodeUtf8 b64) of
        Left err -> fail err
        Right k -> pure $ MachineKey k

-- | Network map (list of all peers and their configuration)
data NetworkMap = NetworkMap
  { nmSelfNode :: !PeerInfo
  -- ^ Information about this node
  , nmPeers :: ![PeerInfo]
  -- ^ List of peer nodes
  , nmDERPMap :: !DERPMap
  -- ^ DERP server configuration
  , nmDNSConfig :: !(Maybe DNSConfig)
  -- ^ DNS configuration
  , nmPacketFilter :: !(Maybe [FilterRule])
  -- ^ ACL filter rules
  , nmCollectServices :: !Bool
  -- ^ Whether to collect service info
  , nmDomain :: !Text
  -- ^ Tailnet domain (e.g., "tail-scale.ts.net")
  }
  deriving (Eq, Show, Generic)

instance FromJSON NetworkMap where
  parseJSON = withObject "NetworkMap" $ \o ->
    NetworkMap
      <$> o .: "SelfNode"
      <*> o .:? "Peers" .!= []
      <*> o .: "DERPMap"
      <*> o .:? "DNSConfig"
      <*> o .:? "PacketFilter"
      <*> o .:? "CollectServices" .!= False
      <*> o .:? "Domain" .!= ""

-- | Information about a peer
data PeerInfo = PeerInfo
  { piID :: !Int
  -- ^ Node ID
  , piStableID :: !Text
  -- ^ Stable node ID
  , piName :: !Text
  -- ^ Node name
  , piUser :: !Int
  -- ^ User ID
  , piKey :: !NodeKey
  -- ^ WireGuard public key
  , piAddresses :: ![Text]
  -- ^ Tailscale IP addresses
  , piAllowedIPs :: ![Text]
  -- ^ Allowed IP ranges
  , piEndpoints :: !(Maybe [Text])
  -- ^ Direct endpoints (IP:port)
  , piDERP :: !(Maybe Text)
  -- ^ Preferred DERP region
  , piHostinfo :: !(Maybe Value)
  -- ^ Host information
  , piCreated :: !(Maybe UTCTime)
  -- ^ Creation time
  , piLastSeen :: !(Maybe UTCTime)
  -- ^ Last seen time
  , piOnline :: !(Maybe Bool)
  -- ^ Whether the peer is online
  , piKeepAlive :: !Bool
  -- ^ Whether to send keepalives
  , piMachineAuthorized :: !Bool
  -- ^ Whether the machine is authorized
  , piTags :: !(Maybe [Text])
  -- ^ ACL tags
  }
  deriving (Eq, Show, Generic)

instance FromJSON PeerInfo where
  parseJSON = withObject "PeerInfo" $ \o ->
    PeerInfo
      <$> o .: "ID"
      <*> o .: "StableID"
      <*> o .: "Name"
      <*> o .: "User"
      <*> o .: "Key"
      <*> o .:? "Addresses" .!= []
      <*> o .:? "AllowedIPs" .!= []
      <*> o .:? "Endpoints"
      <*> o .:? "DERP"
      <*> o .:? "Hostinfo"
      <*> o .:? "Created"
      <*> o .:? "LastSeen"
      <*> o .:? "Online"
      <*> o .:? "KeepAlive" .!= False
      <*> o .:? "MachineAuthorized" .!= False
      <*> o .:? "Tags"

-- | DERP map (relay server configuration)
data DERPMap = DERPMap
  { dmRegions :: !(Map Int DERPRegion)
  -- ^ DERP regions by ID
  , dmOmitDefaultRegions :: !Bool
  -- ^ Whether to omit default Tailscale regions
  }
  deriving (Eq, Show, Generic)

instance FromJSON DERPMap where
  parseJSON = withObject "DERPMap" $ \o ->
    DERPMap
      <$> o .:? "Regions" .!= Map.empty
      <*> o .:? "OmitDefaultRegions" .!= False

-- | DERP region
data DERPRegion = DERPRegion
  { drRegionID :: !Int
  , drRegionCode :: !Text
  , drRegionName :: !Text
  , drNodes :: ![DERPNode]
  , drAvoid :: !Bool
  }
  deriving (Eq, Show, Generic)

instance FromJSON DERPRegion where
  parseJSON = withObject "DERPRegion" $ \o ->
    DERPRegion
      <$> o .: "RegionID"
      <*> o .: "RegionCode"
      <*> o .: "RegionName"
      <*> o .:? "Nodes" .!= []
      <*> o .:? "Avoid" .!= False

-- | DERP node (individual server)
data DERPNode = DERPNode
  { dnName :: !Text
  , dnRegionID :: !Int
  , dnHostName :: !Text
  , dnIPv4 :: !(Maybe Text)
  , dnIPv6 :: !(Maybe Text)
  , dnSTUNPort :: !Word16
  , dnSTUNOnly :: !Bool
  , dnDERPPort :: !Word16
  }
  deriving (Eq, Show, Generic)

instance FromJSON DERPNode where
  parseJSON = withObject "DERPNode" $ \o ->
    DERPNode
      <$> o .: "Name"
      <*> o .: "RegionID"
      <*> o .: "HostName"
      <*> o .:? "IPv4"
      <*> o .:? "IPv6"
      <*> o .:? "STUNPort" .!= 3478
      <*> o .:? "STUNOnly" .!= False
      <*> o .:? "DERPPort" .!= 443

-- | DNS configuration from control server
data DNSConfig = DNSConfig
  { dnsResolvers :: ![Text]
  , dnsDomains :: ![Text]
  , dnsRoutes :: !(Map Text [Text])
  , dnsProxied :: !Bool
  }
  deriving (Eq, Show, Generic)

instance FromJSON DNSConfig where
  parseJSON = withObject "DNSConfig" $ \o ->
    DNSConfig
      <$> o .:? "Resolvers" .!= []
      <*> o .:? "Domains" .!= []
      <*> o .:? "Routes" .!= Map.empty
      <*> o .:? "Proxied" .!= False

-- | ACL filter rule
data FilterRule = FilterRule
  { frSrcIPs :: ![Text]
  , frDstPorts :: ![Text]
  }
  deriving (Eq, Show, Generic)

instance FromJSON FilterRule where
  parseJSON = withObject "FilterRule" $ \o ->
    FilterRule
      <$> o .:? "SrcIPs" .!= []
      <*> o .:? "DstPorts" .!= []

--------------------------------------------------------------------------------
-- Registration
--------------------------------------------------------------------------------

-- | Request to register with control server
data RegisterRequest = RegisterRequest
  { rrVersion :: !Int
  , rrNodeKey :: !NodeKey
  , rrOldNodeKey :: !(Maybe NodeKey)
  , rrAuth :: !(Maybe AuthInfo)
  , rrExpiry :: !(Maybe UTCTime)
  , rrHostinfo :: !(Maybe Value)
  , rrFollowup :: !(Maybe Text)
  }
  deriving (Eq, Show, Generic)

instance ToJSON RegisterRequest where
  toJSON RegisterRequest{..} =
    object
      [ "Version" .= rrVersion
      , "NodeKey" .= rrNodeKey
      , "OldNodeKey" .= rrOldNodeKey
      , "Auth" .= rrAuth
      , "Expiry" .= rrExpiry
      , "Hostinfo" .= rrHostinfo
      , "Followup" .= rrFollowup
      ]

-- | Authentication information
data AuthInfo = AuthInfo
  { aiProvider :: !Text
  , aiLoginName :: !(Maybe Text)
  , aiAuthKey :: !(Maybe Text)
  }
  deriving (Eq, Show, Generic)

instance ToJSON AuthInfo where
  toJSON AuthInfo{..} =
    object
      [ "Provider" .= aiProvider
      , "LoginName" .= aiLoginName
      , "AuthKey" .= aiAuthKey
      ]

-- | Response from registration
data RegisterResponse = RegisterResponse
  { rrspUser :: !(Maybe UserInfo)
  , rrspLogin :: !(Maybe LoginInfo)
  , rrspNodeKeyExpired :: !Bool
  , rrspMachineAuthorized :: !Bool
  , rrspAuthURL :: !(Maybe Text)
  , rrspError :: !(Maybe Text)
  }
  deriving (Eq, Show, Generic)

instance FromJSON RegisterResponse where
  parseJSON = withObject "RegisterResponse" $ \o ->
    RegisterResponse
      <$> o .:? "User"
      <*> o .:? "Login"
      <*> o .:? "NodeKeyExpired" .!= False
      <*> o .:? "MachineAuthorized" .!= False
      <*> o .:? "AuthURL"
      <*> o .:? "Error"

data UserInfo = UserInfo
  { uiID :: !Int
  , uiLoginName :: !Text
  , uiDisplayName :: !Text
  }
  deriving (Eq, Show, Generic)

instance FromJSON UserInfo where
  parseJSON = withObject "UserInfo" $ \o ->
    UserInfo
      <$> o .: "ID"
      <*> o .: "LoginName"
      <*> o .: "DisplayName"

data LoginInfo = LoginInfo
  { liID :: !Int
  , liProvider :: !Text
  , liLoginName :: !Text
  }
  deriving (Eq, Show, Generic)

instance FromJSON LoginInfo where
  parseJSON = withObject "LoginInfo" $ \o ->
    LoginInfo
      <$> o .: "ID"
      <*> o .: "Provider"
      <*> o .: "LoginName"

--------------------------------------------------------------------------------
-- Map Requests
--------------------------------------------------------------------------------

-- | Request for network map
data MapRequest = MapRequest
  { mrVersion :: !Int
  , mrCompress :: !Text
  -- ^ "zstd" or ""
  , mrKeepAlive :: !Bool
  , mrNodeKey :: !NodeKey
  , mrEndpoints :: ![Text]
  , mrStream :: !Bool
  , mrHostinfo :: !(Maybe Value)
  }
  deriving (Eq, Show, Generic)

instance ToJSON MapRequest where
  toJSON MapRequest{..} =
    object
      [ "Version" .= mrVersion
      , "Compress" .= mrCompress
      , "KeepAlive" .= mrKeepAlive
      , "NodeKey" .= mrNodeKey
      , "Endpoints" .= mrEndpoints
      , "Stream" .= mrStream
      , "Hostinfo" .= mrHostinfo
      ]

-- | Response with network map
data MapResponse = MapResponse
  { mrspNode :: !(Maybe PeerInfo)
  , mrspPeers :: !(Maybe [PeerInfo])
  , mrspDNSConfig :: !(Maybe DNSConfig)
  , mrspDERPMap :: !(Maybe DERPMap)
  , mrspDomain :: !(Maybe Text)
  , mrspPacketFilter :: !(Maybe [FilterRule])
  , mrspUserProfiles :: !(Maybe (Map Int UserInfo))
  , mrspHealth :: !(Maybe [Text])
  , mrspControlTime :: !(Maybe UTCTime)
  }
  deriving (Eq, Show, Generic)

instance FromJSON MapResponse where
  parseJSON = withObject "MapResponse" $ \o ->
    MapResponse
      <$> o .:? "Node"
      <*> o .:? "Peers"
      <*> o .:? "DNSConfig"
      <*> o .:? "DERPMap"
      <*> o .:? "Domain"
      <*> o .:? "PacketFilter"
      <*> o .:? "UserProfiles"
      <*> o .:? "Health"
      <*> o .:? "ControlTime"
