{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

{- |
Module      : Tailscale.Types
Description : Core types for the Tailscale API
License     : BSD-3-Clause

This module contains all the data types used by the Tailscale API client.
It is a direct port of the types defined in the Tailscale Go SDK.
-}
module Tailscale.Types (
  -- * Error Types
  TailscaleError (..),
  ErrResponse (..),

  -- * Device Types
  Device (..),
  ClientConnectivity (..),
  DerpRegion (..),
  DevicePostureIdentity (..),
  DeviceFieldsOpts (..),
  deviceAllFields,
  deviceDefaultFields,

  -- * DNS Types
  DNSConfig (..),
  DNSNameServers (..),
  DNSNameServersPostResponse (..),
  DNSSearchPaths (..),
  DNSPreferences (..),

  -- * Key Types
  Key (..),
  KeyCapabilities (..),
  KeyDeviceCapabilities (..),
  KeyDeviceCreateCapabilities (..),

  -- * ACL Types
  ACL (..),
  ACLDetails (..),
  ACLRow (..),
  ACLTest (..),
  NodeAttrGrant (..),
  ACLHuJSON (..),
  ACLTestError (..),
  ACLTestFailureSummary (..),
  ACLPreview (..),
  UserRuleMatch (..),

  -- * Routes Types
  Routes (..),
) where

import Data.Aeson hiding (Key)
import Data.Map.Strict (Map)
import Data.Text (Text)
import Data.Time (UTCTime)
import GHC.Generics (Generic)

--------------------------------------------------------------------------------
-- Error Types
--------------------------------------------------------------------------------

-- | Error response from the Tailscale API
data ErrResponse = ErrResponse
  { errStatus :: !Int
  , errMessage :: !Text
  }
  deriving (Eq, Show, Generic)

instance FromJSON ErrResponse where
  parseJSON = withObject "ErrResponse" $ \o ->
    ErrResponse
      <$> o .: "status"
      <*> o .: "message"

instance ToJSON ErrResponse where
  toJSON ErrResponse{..} =
    object
      [ "status" .= errStatus
      , "message" .= errMessage
      ]

-- | Errors that can occur when using the Tailscale client
data TailscaleError
  = ApiError !ErrResponse
  | HttpError !Text
  | JsonError !Text
  | NetworkError !Text
  deriving (Eq, Show)

--------------------------------------------------------------------------------
-- Device Types
--------------------------------------------------------------------------------

-- | Represents a device (node) in a Tailscale network
data Device = Device
  { deviceAddresses :: ![Text]
  , deviceId :: !Text
  , deviceNodeId :: !Text
  , deviceUser :: !Text
  , deviceName :: !Text
  , deviceHostname :: !Text
  , deviceClientVersion :: !(Maybe Text)
  , deviceUpdateAvailable :: !(Maybe Bool)
  , deviceOs :: !(Maybe Text)
  , deviceCreated :: !(Maybe UTCTime)
  , deviceLastSeen :: !(Maybe UTCTime)
  , deviceKeyExpiryDisabled :: !(Maybe Bool)
  , deviceExpires :: !(Maybe UTCTime)
  , deviceAuthorized :: !(Maybe Bool)
  , deviceIsExternal :: !(Maybe Bool)
  , deviceMachineKey :: !(Maybe Text)
  , deviceNodeKey :: !(Maybe Text)
  , deviceBlocksIncomingConnections :: !(Maybe Bool)
  , deviceEnabledRoutes :: !(Maybe [Text])
  , deviceAdvertisedRoutes :: !(Maybe [Text])
  , deviceClientConnectivity :: !(Maybe ClientConnectivity)
  , deviceTags :: !(Maybe [Text])
  , devicePostureIdentity :: !(Maybe DevicePostureIdentity)
  , deviceTailnetLockKey :: !(Maybe Text)
  , deviceTailnetLockError :: !(Maybe Text)
  }
  deriving (Eq, Show, Generic)

instance FromJSON Device where
  parseJSON = withObject "Device" $ \o ->
    Device
      <$> o .: "addresses"
      <*> o .: "id"
      <*> o .: "nodeId"
      <*> o .: "user"
      <*> o .: "name"
      <*> o .: "hostname"
      <*> o .:? "clientVersion"
      <*> o .:? "updateAvailable"
      <*> o .:? "os"
      <*> o .:? "created"
      <*> o .:? "lastSeen"
      <*> o .:? "keyExpiryDisabled"
      <*> o .:? "expires"
      <*> o .:? "authorized"
      <*> o .:? "isExternal"
      <*> o .:? "machineKey"
      <*> o .:? "nodeKey"
      <*> o .:? "blocksIncomingConnections"
      <*> o .:? "enabledRoutes"
      <*> o .:? "advertisedRoutes"
      <*> o .:? "clientConnectivity"
      <*> o .:? "tags"
      <*> o .:? "postureIdentity"
      <*> o .:? "tailnetLockKey"
      <*> o .:? "tailnetLockError"

instance ToJSON Device where
  toJSON Device{..} =
    object
      [ "addresses" .= deviceAddresses
      , "id" .= deviceId
      , "nodeId" .= deviceNodeId
      , "user" .= deviceUser
      , "name" .= deviceName
      , "hostname" .= deviceHostname
      , "clientVersion" .= deviceClientVersion
      , "updateAvailable" .= deviceUpdateAvailable
      , "os" .= deviceOs
      , "created" .= deviceCreated
      , "lastSeen" .= deviceLastSeen
      , "keyExpiryDisabled" .= deviceKeyExpiryDisabled
      , "expires" .= deviceExpires
      , "authorized" .= deviceAuthorized
      , "isExternal" .= deviceIsExternal
      , "machineKey" .= deviceMachineKey
      , "nodeKey" .= deviceNodeKey
      , "blocksIncomingConnections" .= deviceBlocksIncomingConnections
      , "enabledRoutes" .= deviceEnabledRoutes
      , "advertisedRoutes" .= deviceAdvertisedRoutes
      , "clientConnectivity" .= deviceClientConnectivity
      , "tags" .= deviceTags
      , "postureIdentity" .= devicePostureIdentity
      , "tailnetLockKey" .= deviceTailnetLockKey
      , "tailnetLockError" .= deviceTailnetLockError
      ]

-- | Client connectivity information for a device
data ClientConnectivity = ClientConnectivity
  { ccEndpoints :: ![Text]
  , ccDerp :: !Text
  , ccMappingVariesByDestIP :: !Bool
  , ccLatency :: !(Map Text DerpRegion)
  , ccClientSupports :: !(Maybe (Map Text Bool))
  }
  deriving (Eq, Show, Generic)

instance FromJSON ClientConnectivity where
  parseJSON = withObject "ClientConnectivity" $ \o ->
    ClientConnectivity
      <$> o .: "endpoints"
      <*> o .: "derp"
      <*> o .: "mappingVariesByDestIP"
      <*> o .: "latency"
      <*> o .:? "clientSupports"

instance ToJSON ClientConnectivity where
  toJSON ClientConnectivity{..} =
    object
      [ "endpoints" .= ccEndpoints
      , "derp" .= ccDerp
      , "mappingVariesByDestIP" .= ccMappingVariesByDestIP
      , "latency" .= ccLatency
      , "clientSupports" .= ccClientSupports
      ]

-- | DERP region latency information
data DerpRegion = DerpRegion
  { drPreferred :: !Bool
  , drLatencyMs :: !Double
  }
  deriving (Eq, Show, Generic)

instance FromJSON DerpRegion where
  parseJSON = withObject "DerpRegion" $ \o ->
    DerpRegion
      <$> o .: "preferred"
      <*> o .: "latencyMs"

instance ToJSON DerpRegion where
  toJSON DerpRegion{..} =
    object
      [ "preferred" .= drPreferred
      , "latencyMs" .= drLatencyMs
      ]

-- | Device posture identity information
data DevicePostureIdentity = DevicePostureIdentity
  { dpiDisabled :: !Bool
  , dpiSerialNumbers :: !(Maybe [Text])
  }
  deriving (Eq, Show, Generic)

instance FromJSON DevicePostureIdentity where
  parseJSON = withObject "DevicePostureIdentity" $ \o ->
    DevicePostureIdentity
      <$> o .: "disabled"
      <*> o .:? "serialNumbers"

instance ToJSON DevicePostureIdentity where
  toJSON DevicePostureIdentity{..} =
    object
      [ "disabled" .= dpiDisabled
      , "serialNumbers" .= dpiSerialNumbers
      ]

-- | Options for which fields to include when fetching devices
newtype DeviceFieldsOpts = DeviceFieldsOpts {unDeviceFieldsOpts :: Text}
  deriving (Eq, Show)

-- | Include all device fields in the response
deviceAllFields :: DeviceFieldsOpts
deviceAllFields = DeviceFieldsOpts "all"

-- | Include only default device fields in the response
deviceDefaultFields :: DeviceFieldsOpts
deviceDefaultFields = DeviceFieldsOpts "default"

--------------------------------------------------------------------------------
-- DNS Types
--------------------------------------------------------------------------------

-- | Full DNS configuration for a tailnet
data DNSConfig = DNSConfig
  { dnsResolvers :: ![Text]
  , dnsFallbackResolvers :: ![Text]
  , dnsDomains :: ![Text]
  , dnsRoutes :: !(Map Text [Text])
  , dnsMagicDNS :: !Bool
  , dnsMagicDNSSuffix :: !Text
  }
  deriving (Eq, Show, Generic)

instance FromJSON DNSConfig where
  parseJSON = withObject "DNSConfig" $ \o ->
    DNSConfig
      <$> o .:? "resolvers" .!= []
      <*> o .:? "fallbackResolvers" .!= []
      <*> o .:? "domains" .!= []
      <*> o .:? "routes" .!= mempty
      <*> o .:? "magicDNS" .!= False
      <*> o .:? "magicDNSSuffix" .!= ""

instance ToJSON DNSConfig where
  toJSON DNSConfig{..} =
    object
      [ "resolvers" .= dnsResolvers
      , "fallbackResolvers" .= dnsFallbackResolvers
      , "domains" .= dnsDomains
      , "routes" .= dnsRoutes
      , "magicDNS" .= dnsMagicDNS
      , "magicDNSSuffix" .= dnsMagicDNSSuffix
      ]

-- | DNS nameservers
newtype DNSNameServers = DNSNameServers
  { dnsNameServers :: [Text]
  }
  deriving (Eq, Show, Generic)

instance FromJSON DNSNameServers where
  parseJSON = withObject "DNSNameServers" $ \o ->
    DNSNameServers <$> o .: "dns"

instance ToJSON DNSNameServers where
  toJSON DNSNameServers{..} =
    object
      [ "dns" .= dnsNameServers
      ]

-- | Response from setting DNS nameservers
data DNSNameServersPostResponse = DNSNameServersPostResponse
  { dnsnsrDns :: ![Text]
  , dnsnsrMagicDNS :: !Bool
  }
  deriving (Eq, Show, Generic)

instance FromJSON DNSNameServersPostResponse where
  parseJSON = withObject "DNSNameServersPostResponse" $ \o ->
    DNSNameServersPostResponse
      <$> o .: "dns"
      <*> o .: "magicDNS"

instance ToJSON DNSNameServersPostResponse where
  toJSON DNSNameServersPostResponse{..} =
    object
      [ "dns" .= dnsnsrDns
      , "magicDNS" .= dnsnsrMagicDNS
      ]

-- | DNS search paths
newtype DNSSearchPaths = DNSSearchPaths
  { dnsSearchPaths :: [Text]
  }
  deriving (Eq, Show, Generic)

instance FromJSON DNSSearchPaths where
  parseJSON = withObject "DNSSearchPaths" $ \o ->
    DNSSearchPaths <$> o .: "searchPaths"

instance ToJSON DNSSearchPaths where
  toJSON DNSSearchPaths{..} =
    object
      [ "searchPaths" .= dnsSearchPaths
      ]

-- | DNS preferences (MagicDNS setting)
newtype DNSPreferences = DNSPreferences
  { dpMagicDNS :: Bool
  }
  deriving (Eq, Show, Generic)

instance FromJSON DNSPreferences where
  parseJSON = withObject "DNSPreferences" $ \o ->
    DNSPreferences <$> o .: "magicDNS"

instance ToJSON DNSPreferences where
  toJSON DNSPreferences{..} =
    object
      [ "magicDNS" .= dpMagicDNS
      ]

--------------------------------------------------------------------------------
-- Key Types
--------------------------------------------------------------------------------

-- | An authentication key for the Tailscale API
data Key = Key
  { keyId :: !Text
  , keyCreated :: !UTCTime
  , keyExpires :: !UTCTime
  , keyCapabilities :: !KeyCapabilities
  , keyDescription :: !(Maybe Text)
  }
  deriving (Eq, Show, Generic)

instance FromJSON Key where
  parseJSON = withObject "Key" $ \o ->
    Key
      <$> o .: "id"
      <*> o .: "created"
      <*> o .: "expires"
      <*> o .: "capabilities"
      <*> o .:? "description"

instance ToJSON Key where
  toJSON Key{..} =
    object
      [ "id" .= keyId
      , "created" .= keyCreated
      , "expires" .= keyExpires
      , "capabilities" .= keyCapabilities
      , "description" .= keyDescription
      ]

-- | Key capabilities
newtype KeyCapabilities = KeyCapabilities
  { kcDevices :: Maybe KeyDeviceCapabilities
  }
  deriving (Eq, Show, Generic)

instance FromJSON KeyCapabilities where
  parseJSON = withObject "KeyCapabilities" $ \o ->
    KeyCapabilities <$> o .:? "devices"

instance ToJSON KeyCapabilities where
  toJSON KeyCapabilities{..} =
    object
      [ "devices" .= kcDevices
      ]

-- | Device-related key capabilities
newtype KeyDeviceCapabilities = KeyDeviceCapabilities
  { kdcCreate :: KeyDeviceCreateCapabilities
  }
  deriving (Eq, Show, Generic)

instance FromJSON KeyDeviceCapabilities where
  parseJSON = withObject "KeyDeviceCapabilities" $ \o ->
    KeyDeviceCapabilities <$> o .: "create"

instance ToJSON KeyDeviceCapabilities where
  toJSON KeyDeviceCapabilities{..} =
    object
      [ "create" .= kdcCreate
      ]

-- | Capabilities for creating devices with a key
data KeyDeviceCreateCapabilities = KeyDeviceCreateCapabilities
  { kdccReusable :: !Bool
  , kdccEphemeral :: !Bool
  , kdccPreauthorized :: !Bool
  , kdccTags :: !(Maybe [Text])
  }
  deriving (Eq, Show, Generic)

instance FromJSON KeyDeviceCreateCapabilities where
  parseJSON = withObject "KeyDeviceCreateCapabilities" $ \o ->
    KeyDeviceCreateCapabilities
      <$> o .:? "reusable" .!= False
      <*> o .:? "ephemeral" .!= False
      <*> o .:? "preauthorized" .!= False
      <*> o .:? "tags"

instance ToJSON KeyDeviceCreateCapabilities where
  toJSON KeyDeviceCreateCapabilities{..} =
    object
      [ "reusable" .= kdccReusable
      , "ephemeral" .= kdccEphemeral
      , "preauthorized" .= kdccPreauthorized
      , "tags" .= kdccTags
      ]

--------------------------------------------------------------------------------
-- ACL Types
--------------------------------------------------------------------------------

-- | A single ACL rule
data ACLRow = ACLRow
  { aclAction :: !(Maybe Text)
  , aclProto :: !(Maybe Text)
  , aclUsers :: !(Maybe [Text])
  , aclPorts :: !(Maybe [Text])
  , aclSrc :: !(Maybe [Text])
  , aclDst :: !(Maybe [Text])
  }
  deriving (Eq, Show, Generic)

instance FromJSON ACLRow where
  parseJSON = withObject "ACLRow" $ \o ->
    ACLRow
      <$> o .:? "action"
      <*> o .:? "proto"
      <*> o .:? "users"
      <*> o .:? "ports"
      <*> o .:? "src"
      <*> o .:? "dst"

instance ToJSON ACLRow where
  toJSON ACLRow{..} =
    object
      [ "action" .= aclAction
      , "proto" .= aclProto
      , "users" .= aclUsers
      , "ports" .= aclPorts
      , "src" .= aclSrc
      , "dst" .= aclDst
      ]

-- | An ACL test case
data ACLTest = ACLTest
  { atSrc :: !(Maybe Text)
  , atUser :: !(Maybe Text)
  , atProto :: !(Maybe Text)
  , atAccept :: !(Maybe [Text])
  , atDeny :: !(Maybe [Text])
  , atAllow :: !(Maybe [Text])
  }
  deriving (Eq, Show, Generic)

instance FromJSON ACLTest where
  parseJSON = withObject "ACLTest" $ \o ->
    ACLTest
      <$> o .:? "src"
      <*> o .:? "user"
      <*> o .:? "proto"
      <*> o .:? "accept"
      <*> o .:? "deny"
      <*> o .:? "allow"

instance ToJSON ACLTest where
  toJSON ACLTest{..} =
    object
      [ "src" .= atSrc
      , "user" .= atUser
      , "proto" .= atProto
      , "accept" .= atAccept
      , "deny" .= atDeny
      , "allow" .= atAllow
      ]

-- | Node attribute grant
data NodeAttrGrant = NodeAttrGrant
  { nagTarget :: !(Maybe [Text])
  , nagAttr :: !(Maybe [Text])
  }
  deriving (Eq, Show, Generic)

instance FromJSON NodeAttrGrant where
  parseJSON = withObject "NodeAttrGrant" $ \o ->
    NodeAttrGrant
      <$> o .:? "target"
      <*> o .:? "attr"

instance ToJSON NodeAttrGrant where
  toJSON NodeAttrGrant{..} =
    object
      [ "target" .= nagTarget
      , "attr" .= nagAttr
      ]

-- | Full ACL details
data ACLDetails = ACLDetails
  { aclTests :: !(Maybe [ACLTest])
  , aclAcls :: !(Maybe [ACLRow])
  , aclGroups :: !(Maybe (Map Text [Text]))
  , aclTagOwners :: !(Maybe (Map Text [Text]))
  , aclHosts :: !(Maybe (Map Text Text))
  , aclNodeAttrs :: !(Maybe [NodeAttrGrant])
  }
  deriving (Eq, Show, Generic)

instance FromJSON ACLDetails where
  parseJSON = withObject "ACLDetails" $ \o ->
    ACLDetails
      <$> o .:? "tests"
      <*> o .:? "acls"
      <*> o .:? "groups"
      <*> o .:? "tagowners"
      <*> o .:? "hosts"
      <*> o .:? "nodeAttrs"

instance ToJSON ACLDetails where
  toJSON ACLDetails{..} =
    object
      [ "tests" .= aclTests
      , "acls" .= aclAcls
      , "groups" .= aclGroups
      , "tagowners" .= aclTagOwners
      , "hosts" .= aclHosts
      , "nodeAttrs" .= aclNodeAttrs
      ]

-- | JSON-parsed ACL with version metadata
data ACL = ACL
  { aclData :: !ACLDetails
  , aclETag :: !(Maybe Text)
  }
  deriving (Eq, Show, Generic)

instance FromJSON ACL where
  parseJSON v = do
    aclData <- parseJSON v
    pure ACL{aclData = aclData, aclETag = Nothing}

instance ToJSON ACL where
  toJSON ACL{..} = toJSON aclData

-- | Human-friendly JSON format ACL (HuJSON)
data ACLHuJSON = ACLHuJSON
  { aclhRaw :: !Text
  , aclhWarnings :: !(Maybe [Text])
  , aclhETag :: !(Maybe Text)
  }
  deriving (Eq, Show, Generic)

-- | Summary of ACL test failures
data ACLTestFailureSummary = ACLTestFailureSummary
  { atfsUser :: !(Maybe Text)
  , atfsErrors :: !(Maybe [Text])
  , atfsWarnings :: !(Maybe [Text])
  }
  deriving (Eq, Show, Generic)

instance FromJSON ACLTestFailureSummary where
  parseJSON = withObject "ACLTestFailureSummary" $ \o ->
    ACLTestFailureSummary
      <$> o .:? "user"
      <*> o .:? "errors"
      <*> o .:? "warnings"

instance ToJSON ACLTestFailureSummary where
  toJSON ACLTestFailureSummary{..} =
    object
      [ "user" .= atfsUser
      , "errors" .= atfsErrors
      , "warnings" .= atfsWarnings
      ]

-- | ACL test error response
data ACLTestError = ACLTestError
  { ateResponse :: !ErrResponse
  , ateData :: ![ACLTestFailureSummary]
  }
  deriving (Eq, Show, Generic)

instance FromJSON ACLTestError where
  parseJSON = withObject "ACLTestError" $ \o ->
    ACLTestError
      <$> (ErrResponse <$> o .: "status" <*> o .: "message")
      <*> o .: "data"

-- | Result of matching a user against ACL rules
data UserRuleMatch = UserRuleMatch
  { urmUsers :: ![Text]
  , urmPorts :: ![Text]
  , urmLineNumber :: !Int
  , urmVia :: !(Maybe [Text])
  , urmPostures :: !(Maybe [Text])
  }
  deriving (Eq, Show, Generic)

instance FromJSON UserRuleMatch where
  parseJSON = withObject "UserRuleMatch" $ \o ->
    UserRuleMatch
      <$> o .: "users"
      <*> o .: "ports"
      <*> o .: "lineNumber"
      <*> o .:? "via"
      <*> o .:? "postures"

instance ToJSON UserRuleMatch where
  toJSON UserRuleMatch{..} =
    object
      [ "users" .= urmUsers
      , "ports" .= urmPorts
      , "lineNumber" .= urmLineNumber
      , "via" .= urmVia
      , "postures" .= urmPostures
      ]

-- | ACL preview result
data ACLPreview = ACLPreview
  { apMatches :: ![UserRuleMatch]
  , apUser :: !(Maybe Text)
  , apIPPort :: !(Maybe Text)
  , apPostures :: !(Maybe (Map Text [Text]))
  }
  deriving (Eq, Show, Generic)

instance FromJSON ACLPreview where
  parseJSON = withObject "ACLPreview" $ \o ->
    ACLPreview
      <$> o .: "matches"
      <*> o .:? "user"
      <*> o .:? "ipport"
      <*> o .:? "postures"

instance ToJSON ACLPreview where
  toJSON ACLPreview{..} =
    object
      [ "matches" .= apMatches
      , "user" .= apUser
      , "ipport" .= apIPPort
      , "postures" .= apPostures
      ]

--------------------------------------------------------------------------------
-- Routes Types
--------------------------------------------------------------------------------

-- | Routes configuration for a device
data Routes = Routes
  { routesAdvertised :: ![Text]
  , routesEnabled :: ![Text]
  }
  deriving (Eq, Show, Generic)

instance FromJSON Routes where
  parseJSON = withObject "Routes" $ \o ->
    Routes
      <$> o .:? "advertisedRoutes" .!= []
      <*> o .:? "enabledRoutes" .!= []

instance ToJSON Routes where
  toJSON Routes{..} =
    object
      [ "advertisedRoutes" .= routesAdvertised
      , "enabledRoutes" .= routesEnabled
      ]
