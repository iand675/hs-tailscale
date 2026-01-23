{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

{- |
Module      : Tailscale.Server
Description : Utilities for running servers on Tailscale
License     : BSD-3-Clause

This module provides utilities for running network servers that appear
as Tailscale services. It works with any network library (Warp, Snap, etc.)
by providing the configuration you need to bind to Tailscale.

= Prerequisites

The tailscaled daemon must be running on the local machine.

= Example: Running a Warp Server

@
import Network.Wai
import Network.Wai.Handler.Warp
import Network.Wai.Handler.WarpTLS
import Tailscale.Server

main :: IO ()
main = do
  -- Get server configuration from Tailscale
  result <- getTailscaleServerConfig
  case result of
    Left err -> error $ "Failed to get Tailscale config: " <> show err
    Right config -> do
      putStrLn $ "Serving on " <> show (tsAddresses config)
      putStrLn $ "HTTPS domain: " <> show (tsCertDomain config)

      -- For HTTPS with automatic Tailscale certificates
      let tlsSettings = tailscaleTLSSettings config
      runTLS tlsSettings (setPort 443 defaultSettings) app

      -- Or for plain HTTP on the Tailscale network
      -- runSettings (setHost (tsBindHost config) $ setPort 80 defaultSettings) app

app :: Application
app req respond = respond $ responseLBS status200 [] \"Hello from Tailscale!\"
@

= Example: Identifying Callers

@
import Tailscale.Server
import Tailscale.LocalAPI

app :: LocalClient -> Application
app client req respond = do
  -- Identify who is calling
  caller <- identifyCaller client req
  case caller of
    Just info -> do
      putStrLn $ \"Request from: \" <> show (callerDisplayName info)
      putStrLn $ \"Login: \" <> show (callerLoginName info)
    Nothing ->
      putStrLn \"Unknown caller\"
  respond $ responseLBS status200 [] \"Hello!\"
@
-}
module Tailscale.Server (
  -- * Server Configuration
  TailscaleServerConfig (..),
  getTailscaleServerConfig,
  getTailscaleServerConfigWith,

  -- * TLS Configuration
  TailscaleTLSConfig (..),
  getTailscaleTLSConfig,
  writeTLSCredentials,

  -- * Caller Identification
  CallerInfo (..),
  identifyCallerByAddr,

  -- * Address Utilities
  tailscaleIPv4,
  tailscaleIPv6,
  isIPv4,
  isIPv6,
) where

import Data.List (find)
import Data.Maybe (fromMaybe, listToMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import System.Directory (createDirectoryIfMissing)
import System.FilePath (takeDirectory)

import Tailscale.LocalAPI

-- | Configuration for a Tailscale server
data TailscaleServerConfig = TailscaleServerConfig
  { tsAddresses :: ![TailscaleIP]
  -- ^ All Tailscale IP addresses for this machine
  , tsIPv4 :: !(Maybe TailscaleIP)
  -- ^ The IPv4 address (100.x.y.z)
  , tsIPv6 :: !(Maybe TailscaleIP)
  -- ^ The IPv6 address (fd7a:...)
  , tsCertDomain :: !(Maybe Text)
  -- ^ The MagicDNS domain for HTTPS certificates
  , tsMagicDNSSuffix :: !(Maybe Text)
  -- ^ The MagicDNS suffix (e.g., "tail-scale.ts.net")
  , tsHostname :: !(Maybe Text)
  -- ^ The hostname of this machine on the tailnet
  , tsLocalClient :: !LocalClient
  -- ^ The LocalClient for further API calls
  }
  deriving (Show)

-- Note: Show instance for LocalClient is defined in Tailscale.LocalAPI.Types

-- | TLS configuration from Tailscale
data TailscaleTLSConfig = TailscaleTLSConfig
  { tlsCertPEM :: !Text
  -- ^ The certificate in PEM format
  , tlsKeyPEM :: !Text
  -- ^ The private key in PEM format
  , tlsDomain :: !Text
  -- ^ The domain this certificate is for
  }
  deriving (Eq, Show)

-- | Information about a caller (from WhoIs)
data CallerInfo = CallerInfo
  { callerNodeName :: !Text
  -- ^ The node name of the caller
  , callerHostname :: !Text
  -- ^ The hostname of the caller
  , callerLoginName :: !Text
  -- ^ The login name (email) of the caller
  , callerDisplayName :: !Text
  -- ^ The display name of the caller
  , callerUserId :: !Int
  -- ^ The user ID of the caller
  , callerNodeId :: !Text
  -- ^ The stable node ID
  , callerTags :: ![Text]
  -- ^ ACL tags on the caller's node
  }
  deriving (Eq, Show)

{- | Get the server configuration from Tailscale using the default socket

This will fail if tailscaled is not running or not connected.
-}
getTailscaleServerConfig :: IO (Either LocalAPIError TailscaleServerConfig)
getTailscaleServerConfig = do
  client <- newLocalClient
  getTailscaleServerConfigWith client

-- | Get the server configuration using a specific LocalClient
getTailscaleServerConfigWith :: LocalClient -> IO (Either LocalAPIError TailscaleServerConfig)
getTailscaleServerConfigWith client = do
  statusResult <- getStatus client
  case statusResult of
    Left err -> pure $ Left err
    Right status -> do
      case statusBackendState status of
        StateRunning -> do
          let ips = fromMaybe [] (statusTailscaleIPs status)
              ipv4 = find isIPv4 ips
              ipv6 = find isIPv6 ips
              certDomains = fromMaybe [] (statusCertDomains status)
              certDomain = listToMaybe certDomains
              hostname = peerHostName <$> statusSelf status
          pure $
            Right
              TailscaleServerConfig
                { tsAddresses = ips
                , tsIPv4 = ipv4
                , tsIPv6 = ipv6
                , tsCertDomain = certDomain
                , tsMagicDNSSuffix = statusMagicDNSSuffix status
                , tsHostname = hostname
                , tsLocalClient = client
                }
        other ->
          pure $
            Left $
              LocalAPIHttpError 503 $
                "Tailscale is not running (state: " <> T.pack (show other) <> ")"

{- | Get TLS configuration (certificate and key) from Tailscale

This fetches a valid TLS certificate for your MagicDNS domain.
Tailscale handles certificate provisioning and renewal automatically.
-}
getTailscaleTLSConfig :: TailscaleServerConfig -> IO (Either LocalAPIError TailscaleTLSConfig)
getTailscaleTLSConfig config = do
  case tsCertDomain config of
    Nothing -> pure $ Left $ LocalAPIHttpError 400 "No certificate domain available"
    Just domain -> do
      certResult <- getCertPair (tsLocalClient config) domain
      case certResult of
        Left err -> pure $ Left err
        Right (CertPair cert key) ->
          pure $
            Right
              TailscaleTLSConfig
                { tlsCertPEM = cert
                , tlsKeyPEM = key
                , tlsDomain = domain
                }

{- | Write TLS credentials to files

This is useful for servers that require file paths for TLS configuration.

@
tlsConfig <- getTailscaleTLSConfig serverConfig
case tlsConfig of
  Right cfg -> do
    writeTLSCredentials cfg \"\/tmp\/tailscale-cert.pem\" \"\/tmp\/tailscale-key.pem\"
    -- Now use these files with your TLS server
  Left err -> print err
@
-}
writeTLSCredentials ::
  TailscaleTLSConfig ->
  -- | Certificate file path
  FilePath ->
  -- | Key file path
  FilePath ->
  IO ()
writeTLSCredentials TailscaleTLSConfig{..} certPath keyPath = do
  createDirectoryIfMissing True (takeDirectory certPath)
  createDirectoryIfMissing True (takeDirectory keyPath)
  TIO.writeFile certPath tlsCertPEM
  TIO.writeFile keyPath tlsKeyPEM

{- | Identify a caller by their remote address

Pass the remote address as "IP:port" or just "IP".
Returns Nothing if the caller cannot be identified.

@
-- Get remote address from your server framework
let remoteAddr = \"100.64.1.2:54321\"
callerInfo <- identifyCallerByAddr client remoteAddr
case callerInfo of
  Just info -> putStrLn $ \"Hello, \" <> callerDisplayName info
  Nothing -> putStrLn \"Unknown caller\"
@
-}
identifyCallerByAddr :: LocalClient -> Text -> IO (Maybe CallerInfo)
identifyCallerByAddr client remoteAddr = do
  result <- whoIs client remoteAddr
  case result of
    Left _ -> pure Nothing
    Right whois ->
      pure $
        Just
          CallerInfo
            { callerNodeName = nodeName (whoIsNode whois)
            , callerHostname = fromMaybe "" $ nodeComputedName (whoIsNode whois)
            , callerLoginName = userProfileLoginName (whoIsUserProfile whois)
            , callerDisplayName = userProfileDisplayName (whoIsUserProfile whois)
            , callerUserId = userProfileID (whoIsUserProfile whois)
            , callerNodeId = nodeStableID (whoIsNode whois)
            , callerTags = fromMaybe [] $ nodeTags (whoIsNode whois)
            }

-- | Extract the IPv4 address from a list of Tailscale IPs
tailscaleIPv4 :: [TailscaleIP] -> Maybe TailscaleIP
tailscaleIPv4 = find isIPv4

-- | Extract the IPv6 address from a list of Tailscale IPs
tailscaleIPv6 :: [TailscaleIP] -> Maybe TailscaleIP
tailscaleIPv6 = find isIPv6

-- | Check if a TailscaleIP is an IPv4 address
isIPv4 :: TailscaleIP -> Bool
isIPv4 (TailscaleIP ip) = T.isPrefixOf "100." ip

-- | Check if a TailscaleIP is an IPv6 address
isIPv6 :: TailscaleIP -> Bool
isIPv6 (TailscaleIP ip) = T.isPrefixOf "fd7a:" ip || T.any (== ':') ip
