{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

{- |
Module      : Tsnet.LocalAPI.Types
Description : Types for the Tailscale LocalAPI
License     : BSD-3-Clause

This module contains types for communicating with the local tailscaled daemon.
The LocalAPI provides access to the running Tailscale instance on the machine.
-}
module Tsnet.LocalAPI.Types (
  -- * Status Types
  Status (..),
  PeerStatus (..),
  TailscaleIP (..),
  BackendState (..),

  -- * WhoIs Types
  WhoIsResponse (..),
  Node (..),
  UserProfile (..),
  CapabilityMap (..),

  -- * Certificate Types
  CertPair (..),

  -- * Preferences
  Prefs (..),

  -- * Ping Types
  PingResult (..),
  PingType (..),

  -- * File Transfer Types
  WaitingFile (..),
  FileTarget (..),

  -- * Serve Config Types
  ServeConfig (..),
  ServeConfigHandler (..),

  -- * Network Lock Types
  NetworkLockStatus (..),

  -- * Error Types
  LocalAPIError (..),
) where

import Data.Aeson
import Data.Map.Strict (Map)
import Data.Text (Text)
import Data.Time (UTCTime)
import GHC.Generics (Generic)

--------------------------------------------------------------------------------
-- Error Types
--------------------------------------------------------------------------------

-- | Errors that can occur when using the LocalAPI
data LocalAPIError
  = LocalAPIHttpError !Int !Text
  | LocalAPIJsonError !Text
  | LocalAPIConnectionError !Text
  | LocalAPIAccessDenied !Text
  | LocalAPIPreconditionsFailed !Text
  | LocalAPIDaemonNotRunning
  deriving (Eq, Show)

--------------------------------------------------------------------------------
-- Backend State
--------------------------------------------------------------------------------

-- | The state of the Tailscale backend
data BackendState
  = StateNoState
  | StateNeedsLogin
  | StateNeedsMachineAuth
  | StateRunning
  | StateStopped
  | StateStarting
  | StateStopping
  deriving (Eq, Show, Generic)

instance FromJSON BackendState where
  parseJSON = withText "BackendState" $ \t -> pure $ case t of
    "NoState" -> StateNoState
    "NeedsLogin" -> StateNeedsLogin
    "NeedsMachineAuth" -> StateNeedsMachineAuth
    "Running" -> StateRunning
    "Stopped" -> StateStopped
    "Starting" -> StateStarting
    "Stopping" -> StateStopping
    _ -> StateNoState

instance ToJSON BackendState where
  toJSON StateNoState = "NoState"
  toJSON StateNeedsLogin = "NeedsLogin"
  toJSON StateNeedsMachineAuth = "NeedsMachineAuth"
  toJSON StateRunning = "Running"
  toJSON StateStopped = "Stopped"
  toJSON StateStarting = "Starting"
  toJSON StateStopping = "Stopping"

--------------------------------------------------------------------------------
-- Tailscale IP
--------------------------------------------------------------------------------

-- | A Tailscale IP address (can be IPv4 or IPv6)
newtype TailscaleIP = TailscaleIP {unTailscaleIP :: Text}
  deriving (Eq, Show, Generic)

instance FromJSON TailscaleIP where
  parseJSON = fmap TailscaleIP . parseJSON

instance ToJSON TailscaleIP where
  toJSON = toJSON . unTailscaleIP

--------------------------------------------------------------------------------
-- Status Types
--------------------------------------------------------------------------------

-- | Status of the local Tailscale daemon
data Status = Status
  { statusBackendState :: !BackendState
  , statusAuthURL :: !(Maybe Text)
  , statusTailscaleIPs :: !(Maybe [TailscaleIP])
  , statusSelf :: !(Maybe PeerStatus)
  , statusPeers :: !(Maybe (Map Text PeerStatus))
  , statusMagicDNSSuffix :: !(Maybe Text)
  , statusCurrentTailnet :: !(Maybe TailnetStatus)
  , statusCertDomains :: !(Maybe [Text])
  , statusVersion :: !(Maybe Text)
  }
  deriving (Eq, Show, Generic)

instance FromJSON Status where
  parseJSON = withObject "Status" $ \o ->
    Status
      <$> o .: "BackendState"
      <*> o .:? "AuthURL"
      <*> o .:? "TailscaleIPs"
      <*> o .:? "Self"
      <*> o .:? "Peer"
      <*> o .:? "MagicDNSSuffix"
      <*> o .:? "CurrentTailnet"
      <*> o .:? "CertDomains"
      <*> o .:? "Version"

-- | Information about the current tailnet
data TailnetStatus = TailnetStatus
  { tailnetName :: !Text
  , tailnetMagicDNSName :: !(Maybe Text)
  , tailnetMagicDNSEnabled :: !(Maybe Bool)
  }
  deriving (Eq, Show, Generic)

instance FromJSON TailnetStatus where
  parseJSON = withObject "TailnetStatus" $ \o ->
    TailnetStatus
      <$> o .: "Name"
      <*> o .:? "MagicDNSName"
      <*> o .:? "MagicDNSEnabled"

-- | Status of a peer (including self)
data PeerStatus = PeerStatus
  { peerID :: !(Maybe Text)
  , peerPublicKey :: !Text
  , peerHostName :: !Text
  , peerDNSName :: !(Maybe Text)
  , peerOS :: !(Maybe Text)
  , peerUserID :: !(Maybe Int)
  , peerTailscaleIPs :: !(Maybe [TailscaleIP])
  , peerAddrs :: !(Maybe [Text])
  , peerCurAddr :: !(Maybe Text)
  , peerRelay :: !(Maybe Text)
  , peerRxBytes :: !(Maybe Int)
  , peerTxBytes :: !(Maybe Int)
  , peerCreated :: !(Maybe UTCTime)
  , peerLastSeen :: !(Maybe UTCTime)
  , peerLastWrite :: !(Maybe UTCTime)
  , peerOnline :: !(Maybe Bool)
  , peerExitNode :: !(Maybe Bool)
  , peerExitNodeOption :: !(Maybe Bool)
  , peerActive :: !(Maybe Bool)
  , peerTags :: !(Maybe [Text])
  , peerInNetworkMap :: !(Maybe Bool)
  , peerInMagicSock :: !(Maybe Bool)
  , peerInEngine :: !(Maybe Bool)
  }
  deriving (Eq, Show, Generic)

instance FromJSON PeerStatus where
  parseJSON = withObject "PeerStatus" $ \o ->
    PeerStatus
      <$> o .:? "ID"
      <*> o .: "PublicKey"
      <*> o .: "HostName"
      <*> o .:? "DNSName"
      <*> o .:? "OS"
      <*> o .:? "UserID"
      <*> o .:? "TailscaleIPs"
      <*> o .:? "Addrs"
      <*> o .:? "CurAddr"
      <*> o .:? "Relay"
      <*> o .:? "RxBytes"
      <*> o .:? "TxBytes"
      <*> o .:? "Created"
      <*> o .:? "LastSeen"
      <*> o .:? "LastWrite"
      <*> o .:? "Online"
      <*> o .:? "ExitNode"
      <*> o .:? "ExitNodeOption"
      <*> o .:? "Active"
      <*> o .:? "Tags"
      <*> o .:? "InNetworkMap"
      <*> o .:? "InMagicSock"
      <*> o .:? "InEngine"

--------------------------------------------------------------------------------
-- WhoIs Types
--------------------------------------------------------------------------------

-- | Response from WhoIs query identifying a connection
data WhoIsResponse = WhoIsResponse
  { whoIsNode :: !Node
  , whoIsUserProfile :: !UserProfile
  , whoIsCapMap :: !(Maybe CapabilityMap)
  }
  deriving (Eq, Show, Generic)

instance FromJSON WhoIsResponse where
  parseJSON = withObject "WhoIsResponse" $ \o ->
    WhoIsResponse
      <$> o .: "Node"
      <*> o .: "UserProfile"
      <*> o .:? "CapMap"

-- | Node information from WhoIs
data Node = Node
  { nodeID :: !Int
  , nodeStableID :: !Text
  , nodeName :: !Text
  , nodeUser :: !Int
  , nodeKey :: !Text
  , nodeKeyExpiry :: !(Maybe UTCTime)
  , nodeMachine :: !(Maybe Text)
  , nodeAddresses :: !(Maybe [Text])
  , nodeAllowedIPs :: !(Maybe [Text])
  , nodeEndpoints :: !(Maybe [Text])
  , nodeDERP :: !(Maybe Text)
  , nodeHostinfo :: !(Maybe Value)
  , nodeCreated :: !(Maybe UTCTime)
  , nodeTags :: !(Maybe [Text])
  , nodeComputedName :: !(Maybe Text)
  , nodeComputedNameWithHost :: !(Maybe Text)
  }
  deriving (Eq, Show, Generic)

instance FromJSON Node where
  parseJSON = withObject "Node" $ \o ->
    Node
      <$> o .: "ID"
      <*> o .: "StableID"
      <*> o .: "Name"
      <*> o .: "User"
      <*> o .: "Key"
      <*> o .:? "KeyExpiry"
      <*> o .:? "Machine"
      <*> o .:? "Addresses"
      <*> o .:? "AllowedIPs"
      <*> o .:? "Endpoints"
      <*> o .:? "DERP"
      <*> o .:? "Hostinfo"
      <*> o .:? "Created"
      <*> o .:? "Tags"
      <*> o .:? "ComputedName"
      <*> o .:? "ComputedNameWithHost"

-- | User profile from WhoIs
data UserProfile = UserProfile
  { userProfileID :: !Int
  , userProfileLoginName :: !Text
  , userProfileDisplayName :: !Text
  , userProfileProfilePicURL :: !(Maybe Text)
  , userProfileRoles :: !(Maybe [Text])
  }
  deriving (Eq, Show, Generic)

instance FromJSON UserProfile where
  parseJSON = withObject "UserProfile" $ \o ->
    UserProfile
      <$> o .: "ID"
      <*> o .: "LoginName"
      <*> o .: "DisplayName"
      <*> o .:? "ProfilePicURL"
      <*> o .:? "Roles"

-- | Capability map from WhoIs
newtype CapabilityMap = CapabilityMap {unCapabilityMap :: Map Text [Text]}
  deriving (Eq, Show, Generic)

instance FromJSON CapabilityMap where
  parseJSON = fmap CapabilityMap . parseJSON

--------------------------------------------------------------------------------
-- Certificate Types
--------------------------------------------------------------------------------

-- | A TLS certificate pair from Tailscale
data CertPair = CertPair
  { certPEM :: !Text
  , keyPEM :: !Text
  }
  deriving (Eq, Show, Generic)

--------------------------------------------------------------------------------
-- Preferences
--------------------------------------------------------------------------------

-- | Tailscale preferences
data Prefs = Prefs
  { prefsControlURL :: !(Maybe Text)
  , prefsRouteAll :: !(Maybe Bool)
  , prefsAllowSingleHosts :: !(Maybe Bool)
  , prefsCorpDNS :: !(Maybe Bool)
  , prefsWantRunning :: !(Maybe Bool)
  , prefsShieldsUp :: !(Maybe Bool)
  , prefsAdvertiseTags :: !(Maybe [Text])
  , prefsHostname :: !(Maybe Text)
  , prefsNotepadURLs :: !(Maybe Bool)
  , prefsForceDaemon :: !(Maybe Bool)
  , prefsAdvertiseRoutes :: !(Maybe [Text])
  , prefsNoSNAT :: !(Maybe Bool)
  , prefsNetfilterMode :: !(Maybe Int)
  , prefsOperatorUser :: !(Maybe Text)
  }
  deriving (Eq, Show, Generic)

instance FromJSON Prefs where
  parseJSON = withObject "Prefs" $ \o ->
    Prefs
      <$> o .:? "ControlURL"
      <*> o .:? "RouteAll"
      <*> o .:? "AllowSingleHosts"
      <*> o .:? "CorpDNS"
      <*> o .:? "WantRunning"
      <*> o .:? "ShieldsUp"
      <*> o .:? "AdvertiseTags"
      <*> o .:? "Hostname"
      <*> o .:? "NotepadURLs"
      <*> o .:? "ForceDaemon"
      <*> o .:? "AdvertiseRoutes"
      <*> o .:? "NoSNAT"
      <*> o .:? "NetfilterMode"
      <*> o .:? "OperatorUser"

instance ToJSON Prefs where
  toJSON Prefs{..} =
    object
      [ "ControlURL" .= prefsControlURL
      , "RouteAll" .= prefsRouteAll
      , "AllowSingleHosts" .= prefsAllowSingleHosts
      , "CorpDNS" .= prefsCorpDNS
      , "WantRunning" .= prefsWantRunning
      , "ShieldsUp" .= prefsShieldsUp
      , "AdvertiseTags" .= prefsAdvertiseTags
      , "Hostname" .= prefsHostname
      , "NotepadURLs" .= prefsNotepadURLs
      , "ForceDaemon" .= prefsForceDaemon
      , "AdvertiseRoutes" .= prefsAdvertiseRoutes
      , "NoSNAT" .= prefsNoSNAT
      , "NetfilterMode" .= prefsNetfilterMode
      , "OperatorUser" .= prefsOperatorUser
      ]

--------------------------------------------------------------------------------
-- Ping Types
--------------------------------------------------------------------------------

-- | Type of ping to perform
data PingType
  = -- | Tailscale-specific ping
    PingTSMP
  | -- | Standard ICMP ping
    PingICMP
  | -- | Ping via PeerAPI
    PingPeerAPI
  deriving (Eq, Show, Generic)

instance ToJSON PingType where
  toJSON PingTSMP = "TSMP"
  toJSON PingICMP = "ICMP"
  toJSON PingPeerAPI = "PeerAPI"

-- | Result of a ping
data PingResult = PingResult
  { pingIP :: !Text
  , pingNodeIP :: !(Maybe Text)
  , pingNodeName :: !(Maybe Text)
  , pingLatencySeconds :: !(Maybe Double)
  , pingEndpoint :: !(Maybe Text)
  , pingDERPRegionID :: !(Maybe Int)
  , pingDERPRegionCode :: !(Maybe Text)
  , pingPeerAPIPort :: !(Maybe Int)
  , pingIsLocalIP :: !(Maybe Bool)
  , pingErr :: !(Maybe Text)
  }
  deriving (Eq, Show, Generic)

instance FromJSON PingResult where
  parseJSON = withObject "PingResult" $ \o ->
    PingResult
      <$> o .: "IP"
      <*> o .:? "NodeIP"
      <*> o .:? "NodeName"
      <*> o .:? "LatencySeconds"
      <*> o .:? "Endpoint"
      <*> o .:? "DERPRegionID"
      <*> o .:? "DERPRegionCode"
      <*> o .:? "PeerAPIPort"
      <*> o .:? "IsLocalIP"
      <*> o .:? "Err"

--------------------------------------------------------------------------------
-- File Transfer Types
--------------------------------------------------------------------------------

-- | A file waiting to be received via Taildrop
data WaitingFile = WaitingFile
  { waitingFileName :: !Text
  , waitingFileSize :: !Int
  }
  deriving (Eq, Show, Generic)

instance FromJSON WaitingFile where
  parseJSON = withObject "WaitingFile" $ \o ->
    WaitingFile
      <$> o .: "Name"
      <*> o .: "Size"

-- | A target for file transfer
data FileTarget = FileTarget
  { fileTargetNode :: !Node
  , fileTargetPeerAPIURL :: !Text
  }
  deriving (Eq, Show, Generic)

instance FromJSON FileTarget where
  parseJSON = withObject "FileTarget" $ \o ->
    FileTarget
      <$> o .: "Node"
      <*> o .: "PeerAPIURL"

--------------------------------------------------------------------------------
-- Serve Config Types
--------------------------------------------------------------------------------

-- | Configuration for Tailscale Serve
data ServeConfig = ServeConfig
  { serveConfigTCP :: !(Maybe (Map Int ServeConfigHandler))
  , serveConfigWeb :: !(Maybe (Map Text (Map Text ServeConfigHandler)))
  , serveConfigAllowFunnel :: !(Maybe (Map Text Bool))
  }
  deriving (Eq, Show, Generic)

instance FromJSON ServeConfig where
  parseJSON = withObject "ServeConfig" $ \o ->
    ServeConfig
      <$> o .:? "TCP"
      <*> o .:? "Web"
      <*> o .:? "AllowFunnel"

instance ToJSON ServeConfig where
  toJSON ServeConfig{..} =
    object
      [ "TCP" .= serveConfigTCP
      , "Web" .= serveConfigWeb
      , "AllowFunnel" .= serveConfigAllowFunnel
      ]

-- | Handler configuration for Tailscale Serve
data ServeConfigHandler = ServeConfigHandler
  { schProxy :: !(Maybe Text)
  , schPath :: !(Maybe Text)
  , schText :: !(Maybe Text)
  , schTCPForward :: !(Maybe Text)
  , schTerminateTLS :: !(Maybe Bool)
  }
  deriving (Eq, Show, Generic)

instance FromJSON ServeConfigHandler where
  parseJSON = withObject "ServeConfigHandler" $ \o ->
    ServeConfigHandler
      <$> o .:? "Proxy"
      <*> o .:? "Path"
      <*> o .:? "Text"
      <*> o .:? "TCPForward"
      <*> o .:? "TerminateTLS"

instance ToJSON ServeConfigHandler where
  toJSON ServeConfigHandler{..} =
    object
      [ "Proxy" .= schProxy
      , "Path" .= schPath
      , "Text" .= schText
      , "TCPForward" .= schTCPForward
      , "TerminateTLS" .= schTerminateTLS
      ]

--------------------------------------------------------------------------------
-- Network Lock Types
--------------------------------------------------------------------------------

-- | Status of Tailscale Network Lock (tailnet key authority)
data NetworkLockStatus = NetworkLockStatus
  { nlsEnabled :: !Bool
  , nlsHead :: !(Maybe Text)
  , nlsPublicKey :: !(Maybe Text)
  , nlsNodeKey :: !(Maybe Text)
  , nlsNodeKeySigned :: !(Maybe Bool)
  , nlsFilteredPeers :: !(Maybe [Text])
  , nlsStateID :: !(Maybe Int)
  }
  deriving (Eq, Show, Generic)

instance FromJSON NetworkLockStatus where
  parseJSON = withObject "NetworkLockStatus" $ \o ->
    NetworkLockStatus
      <$> o .: "Enabled"
      <*> o .:? "Head"
      <*> o .:? "PublicKey"
      <*> o .:? "NodeKey"
      <*> o .:? "NodeKeySigned"
      <*> o .:? "FilteredPeers"
      <*> o .:? "StateID"
