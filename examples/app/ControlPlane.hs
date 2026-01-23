{- |
Control Plane Protocol Example

This example demonstrates the Tailscale control plane protocol:
- Key generation (Node Key, Machine Key)
- Registration request/response structures
- Network map parsing
- DERP map configuration

Run with: cabal run control-plane-example
-}
module Main where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Encode.Pretty as AesonPretty
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import qualified Data.Map.Strict as Map
import qualified Data.Text as T

import Examples.Debug
import Tsnet.Control.Protocol
import Tsnet.Control.Client
import WireGuard.Crypto


main :: IO ()
main = do
  debugSection "Tailscale Control Plane Protocol Demo"

  debugInfo "The control plane is how Tailscale nodes coordinate:"
  debugInfo "- Registration and authentication"
  debugInfo "- Network map distribution"
  debugInfo "- DERP relay configuration"
  debugInfo "- ACL policy distribution"
  separator

  -- Step 1: Key Generation
  debugStep 1 "Generating Identity Keys"

  debugSubStep "Generating Machine Key..."
  debugInfo "The machine key is a stable identifier for this device."
  machineKey <- generateMachineKey
  debugHex "Machine Key" (unMachineKey machineKey)
  debugKeyValue "Encoded" (T.unpack $ encodeKey "mkey:" machineKey)

  debugSubStep "Generating Node Key..."
  debugInfo "The node key is the WireGuard public key for this node."
  (nodePriv, nodeKey) <- generateNodeKey
  debugHex "Node Key" (unNodeKey nodeKey)
  debugKeyValue "Encoded" (T.unpack $ encodeKey "nodekey:" nodeKey)

  debugSuccess "Identity keys generated"
  separator

  -- Step 2: Control Configuration
  debugStep 2 "Control Plane Configuration"

  let config = ControlConfig
        { ccControlURL = defaultControlURL
        , ccMachineKey = machineKey
        , ccNodeKey = nodeKey
        }

  debugSubStep "Configuration:"
  debugTable
    [ ("Control URL", T.unpack $ ccControlURL config)
    , ("Machine Key", take 20 (T.unpack $ encodeKey "mkey:" machineKey) ++ "...")
    , ("Node Key", take 20 (T.unpack $ encodeKey "nodekey:" nodeKey) ++ "...")
    ]

  separator

  -- Step 3: Registration Request
  debugStep 3 "Registration Request Structure"

  debugInfo "Registration requests contain node identity and capabilities."

  let regRequest = RegisterRequest
        { rrVersion = 68  -- Current protocol version
        , rrNodeKey = nodeKey
        , rrOldNodeKey = Nothing
        , rrAuth = Just AuthInfo
            { aiProvider = ""
            , aiLoginName = Nothing
            , aiAuthKey = Just "tskey-auth-example"
            }
        , rrExpiry = Nothing
        , rrHostinfo = Just $ Aeson.object
            [ "OS" Aeson..= ("linux" :: T.Text)
            , "OSVersion" Aeson..= ("5.15.0" :: T.Text)
            , "GoArch" Aeson..= ("amd64" :: T.Text)  -- Pretending for compat
            , "DeviceModel" Aeson..= ("Haskell Application" :: T.Text)
            , "Hostname" Aeson..= ("haskell-demo" :: T.Text)
            ]
        , rrFollowup = Nothing
        }

  debugSubStep "Registration request JSON:"
  debugJson "RegisterRequest" regRequest

  separator

  -- Step 4: Registration Response
  debugStep 4 "Registration Response Structure"

  debugInfo "The server responds with authentication status and user info."

  let mockResponse = RegisterResponse
        { rrspUser = Just UserInfo
            { uiID = 12345
            , uiLoginName = "user@example.com"
            , uiDisplayName = "Demo User"
            }
        , rrspLogin = Just LoginInfo
            { liID = 67890
            , liProvider = "google"
            , liLoginName = "user@example.com"
            }
        , rrspNodeKeyExpired = False
        , rrspMachineAuthorized = True
        , rrspAuthURL = Nothing  -- Set if auth needed
        , rrspError = Nothing
        }

  debugSubStep "Registration response (mock):"
  debugTable
    [ ("User ID", show $ maybe 0 uiID $ rrspUser mockResponse)
    , ("Login Name", T.unpack $ maybe "" uiLoginName $ rrspUser mockResponse)
    , ("Display Name", T.unpack $ maybe "" uiDisplayName $ rrspUser mockResponse)
    , ("Machine Authorized", show $ rrspMachineAuthorized mockResponse)
    , ("Node Key Expired", show $ rrspNodeKeyExpired mockResponse)
    , ("Auth URL", maybe "None" T.unpack $ rrspAuthURL mockResponse)
    ]

  separator

  -- Step 5: Network Map
  debugStep 5 "Network Map Structure"

  debugInfo "The network map contains all peers and their configuration."

  let mockNetworkMap = createMockNetworkMap nodeKey

  debugSubStep "Self node:"
  printPeerInfo $ nmSelfNode mockNetworkMap

  debugSubStep "Peers (" ++ show (length $ nmPeers mockNetworkMap) ++ "):"
  mapM_ printPeerInfo $ nmPeers mockNetworkMap

  debugSubStep "Domain:"
  debugKeyValue "MagicDNS Domain" (T.unpack $ nmDomain mockNetworkMap)

  separator

  -- Step 6: DERP Map
  debugStep 6 "DERP Map Configuration"

  debugInfo "DERP (Detour Encrypted Relay Protocol) provides NAT traversal."
  debugInfo "When direct connections fail, traffic is relayed through DERP."

  let derpMap = nmDERPMap mockNetworkMap

  debugSubStep "DERP regions:"
  mapM_ printDERPRegion $ Map.elems $ dmRegions derpMap

  separator

  -- Step 7: Map Request
  debugStep 7 "Map Request Structure"

  debugInfo "Clients poll for network map updates."

  let mapRequest = MapRequest
        { mrVersion = 68
        , mrCompress = "zstd"
        , mrKeepAlive = True
        , mrNodeKey = nodeKey
        , mrEndpoints = ["192.0.2.1:41641", "[2001:db8::1]:41641"]
        , mrStream = True
        , mrHostinfo = Nothing
        }

  debugSubStep "Map request JSON:"
  debugJson "MapRequest" mapRequest

  separator

  -- Step 8: Filter Rules
  debugStep 8 "ACL Filter Rules"

  debugInfo "The control plane distributes compiled ACL rules."

  let mockRules =
        [ FilterRule
            { frSrcIPs = ["100.64.0.0/10"]
            , frDstPorts = ["*:22", "*:80", "*:443"]
            }
        , FilterRule
            { frSrcIPs = ["tag:server"]
            , frDstPorts = ["*:*"]
            }
        ]

  debugSubStep "Example filter rules:"
  mapM_ printFilterRule mockRules

  separator

  -- Summary
  debugSection "Control Plane Protocol Summary"

  boxed "Protocol Components"
    [ "Registration  - Node identity and authentication"
    , "Network Map   - Peer list and routing info"
    , "DERP Map      - Relay server configuration"
    , "DNS Config    - MagicDNS and custom resolvers"
    , "ACL Filter    - Compiled access control rules"
    , "User Profiles - Identity information"
    ]

  debugTable
    [ ("Protocol Version", "68")
    , ("Control URL", T.unpack defaultControlURL)
    , ("Compression", "zstd")
    , ("Map Poll", "Long-polling with streaming")
    ]

  debugSuccess "Control plane protocol example completed!"


-- | Encode a key with prefix
encodeKey :: T.Text -> a -> T.Text
encodeKey prefix _ = prefix <> "example..."


-- | Create mock network map
createMockNetworkMap :: NodeKey -> NetworkMap
createMockNetworkMap selfKey = NetworkMap
  { nmSelfNode = PeerInfo
      { piID = 1
      , piStableID = "STABLE123"
      , piName = "haskell-demo"
      , piUser = 12345
      , piKey = selfKey
      , piAddresses = ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"]
      , piAllowedIPs = ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"]
      , piEndpoints = Just ["192.0.2.1:41641"]
      , piDERP = Just "derp1.tailscale.com"
      , piHostinfo = Nothing
      , piCreated = Nothing
      , piLastSeen = Nothing
      , piOnline = Just True
      , piKeepAlive = True
      , piMachineAuthorized = True
      , piTags = Nothing
      }
  , nmPeers =
      [ PeerInfo
          { piID = 2
          , piStableID = "STABLE456"
          , piName = "other-node"
          , piUser = 12345
          , piKey = NodeKey $ BS.replicate 32 0x42
          , piAddresses = ["100.64.0.2/32"]
          , piAllowedIPs = ["100.64.0.2/32"]
          , piEndpoints = Just ["203.0.113.5:41641"]
          , piDERP = Just "derp2.tailscale.com"
          , piHostinfo = Nothing
          , piCreated = Nothing
          , piLastSeen = Nothing
          , piOnline = Just True
          , piKeepAlive = False
          , piMachineAuthorized = True
          , piTags = Just ["tag:server"]
          }
      ]
  , nmDERPMap = DERPMap
      { dmRegions = Map.fromList
          [ (1, DERPRegion
              { drRegionID = 1
              , drRegionCode = "nyc"
              , drRegionName = "New York City"
              , drNodes =
                  [ DERPNode
                      { dnName = "nyc1"
                      , dnRegionID = 1
                      , dnHostName = "derp1.tailscale.com"
                      , dnIPv4 = Just "203.0.113.1"
                      , dnIPv6 = Just "2001:db8::1"
                      , dnSTUNPort = 3478
                      , dnSTUNOnly = False
                      , dnDERPPort = 443
                      }
                  ]
              , drAvoid = False
              })
          , (2, DERPRegion
              { drRegionID = 2
              , drRegionCode = "sfo"
              , drRegionName = "San Francisco"
              , drNodes =
                  [ DERPNode
                      { dnName = "sfo1"
                      , dnRegionID = 2
                      , dnHostName = "derp2.tailscale.com"
                      , dnIPv4 = Just "203.0.113.2"
                      , dnIPv6 = Just "2001:db8::2"
                      , dnSTUNPort = 3478
                      , dnSTUNOnly = False
                      , dnDERPPort = 443
                      }
                  ]
              , drAvoid = False
              })
          ]
      , dmOmitDefaultRegions = False
      }
  , nmDNSConfig = Just DNSConfig
      { dnsResolvers = ["100.100.100.100"]
      , dnsDomains = ["tail-scale.ts.net"]
      , dnsRoutes = Map.empty
      , dnsProxied = True
      }
  , nmPacketFilter = Nothing
  , nmCollectServices = False
  , nmDomain = "tail-scale.ts.net"
  }


-- | Print peer info
printPeerInfo :: PeerInfo -> IO ()
printPeerInfo peer = do
  debugKeyValue ("  " ++ T.unpack (piName peer)) ""
  debugTable
    [ ("    ID", show $ piID peer)
    , ("    Addresses", show $ piAddresses peer)
    , ("    DERP", maybe "None" T.unpack $ piDERP peer)
    , ("    Online", maybe "?" show $ piOnline peer)
    ]


-- | Print DERP region
printDERPRegion :: DERPRegion -> IO ()
printDERPRegion region = do
  debugKeyValue ("  " ++ T.unpack (drRegionCode region))
                (T.unpack $ drRegionName region)
  mapM_ printDERPNode $ drNodes region


-- | Print DERP node
printDERPNode :: DERPNode -> IO ()
printDERPNode node = do
  debugTable
    [ ("    " ++ T.unpack (dnName node), T.unpack $ dnHostName node)
    , ("      DERP Port", show $ dnDERPPort node)
    , ("      STUN Port", show $ dnSTUNPort node)
    ]


-- | Print filter rule
printFilterRule :: FilterRule -> IO ()
printFilterRule rule = do
  debugKeyValue "  Source IPs" (show $ frSrcIPs rule)
  debugKeyValue "  Dest Ports" (show $ frDstPorts rule)
  debugLn ""
