{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module TypesSpec (tests) where

import Data.Aeson hiding (Key)
import qualified Data.ByteString.Lazy as LBS
import Data.Text (Text)
import Test.Tasty
import Test.Tasty.HUnit

import Tailscale.Types

tests :: TestTree
tests =
  testGroup
    "Types"
    [ testGroup
        "Device"
        [ testCase "Device parses minimal JSON" $ do
            let json =
                  "{\"id\":\"123\",\"nodeId\":\"node-123\",\"name\":\"test-device\"\
                  \,\"hostname\":\"test\",\"addresses\":[\"100.100.100.1\"]\
                  \,\"user\":\"user@example.com\",\"os\":\"linux\"\
                  \,\"created\":\"2024-01-01T00:00:00Z\",\"lastSeen\":\"2024-01-01T00:00:00Z\"\
                  \,\"authorized\":true,\"isExternal\":false,\"nodeKey\":\"nodekey:abc\"\
                  \,\"machineKey\":\"mkey:def\",\"blocksIncomingConnections\":false\
                  \,\"enabledRoutes\":[],\"advertisedRoutes\":[]}"
            case eitherDecode json of
              Left err -> assertFailure $ "Parse failed: " <> err
              Right (device :: Device) -> do
                deviceId device @?= "123"
                deviceName device @?= "test-device"
                deviceHostname device @?= "test"
                deviceAddresses device @?= ["100.100.100.1"]
                deviceAuthorized device @?= Just True
        , testCase "Device parses with optional fields" $ do
            let json =
                  "{\"id\":\"456\",\"nodeId\":\"node-456\",\"name\":\"tagged-device\"\
                  \,\"hostname\":\"tagged\",\"addresses\":[\"100.100.100.2\"]\
                  \,\"user\":\"user@example.com\",\"os\":\"macos\"\
                  \,\"created\":\"2024-01-01T00:00:00Z\",\"lastSeen\":\"2024-01-01T00:00:00Z\"\
                  \,\"authorized\":false,\"isExternal\":false,\"nodeKey\":\"nodekey:xyz\"\
                  \,\"machineKey\":\"mkey:uvw\",\"blocksIncomingConnections\":true\
                  \,\"enabledRoutes\":[\"10.0.0.0/8\"],\"advertisedRoutes\":[\"10.0.0.0/8\"]\
                  \,\"tags\":[\"tag:server\",\"tag:prod\"]}"
            case eitherDecode json of
              Left err -> assertFailure $ "Parse failed: " <> err
              Right (device :: Device) -> do
                deviceId device @?= "456"
                deviceTags device @?= Just ["tag:server", "tag:prod"]
                deviceBlocksIncomingConnections device @?= Just True
        ]
    , testGroup
        "Key"
        [ testCase "Key parses JSON" $ do
            let json =
                  "{\"id\":\"key-id-123\",\"created\":\"2024-01-01T00:00:00Z\"\
                  \,\"expires\":\"2024-04-01T00:00:00Z\"\
                  \,\"capabilities\":{\"devices\":{\"create\":{}}}}"
            case eitherDecode json of
              Left err -> assertFailure $ "Parse failed: " <> err
              Right (key :: Key) -> do
                keyId key @?= "key-id-123"
        ]
    , testGroup
        "Routes"
        [ testCase "Routes parses JSON" $ do
            let json =
                  "{\"advertisedRoutes\":[\"10.0.0.0/8\",\"192.168.0.0/16\"]\
                  \,\"enabledRoutes\":[\"10.0.0.0/8\"]}"
            case eitherDecode json of
              Left err -> assertFailure $ "Parse failed: " <> err
              Right (routes :: Routes) -> do
                routesAdvertised routes @?= ["10.0.0.0/8", "192.168.0.0/16"]
                routesEnabled routes @?= ["10.0.0.0/8"]
        ]
    , testGroup
        "DNS"
        [ testCase "DNSNameServers parses JSON" $ do
            let json = "{\"dns\":[\"8.8.8.8\",\"8.8.4.4\"]}"
            case eitherDecode json of
              Left err -> assertFailure $ "Parse failed: " <> err
              Right (dns :: DNSNameServers) -> do
                dnsNameServers dns @?= ["8.8.8.8", "8.8.4.4"]
        , testCase "DNSSearchPaths parses JSON" $ do
            let json = "{\"searchPaths\":[\"example.com\",\"corp.example.com\"]}"
            case eitherDecode json of
              Left err -> assertFailure $ "Parse failed: " <> err
              Right (paths :: DNSSearchPaths) -> do
                dnsSearchPaths paths @?= ["example.com", "corp.example.com"]
        , testCase "DNSPreferences parses JSON" $ do
            let json = "{\"magicDNS\":true}"
            case eitherDecode json of
              Left err -> assertFailure $ "Parse failed: " <> err
              Right (prefs :: DNSPreferences) -> do
                dpMagicDNS prefs @?= True
        ]
    , testGroup
        "ErrResponse"
        [ testCase "ErrResponse parses JSON" $ do
            let json =
                  "{\"status\":404,\"message\":\"Not found\"}"
            case eitherDecode json of
              Left err -> assertFailure $ "Parse failed: " <> err
              Right (errResp :: ErrResponse) -> do
                errStatus errResp @?= 404
                errMessage errResp @?= "Not found"
        ]
    , testGroup
        "DeviceFieldsOpts"
        [ testCase "deviceAllFields contains 'all'" $ do
            let (DeviceFieldsOpts f) = deviceAllFields
            f @?= "all"
        , testCase "deviceDefaultFields contains 'default'" $ do
            let (DeviceFieldsOpts f) = deviceDefaultFields
            f @?= "default"
        ]
    ]
