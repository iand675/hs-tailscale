{-# LANGUAGE OverloadedStrings #-}

-- | Configuration management for Tailscale
module Network.Tailscale.Config
  ( -- * Configuration Types
    Config(..)
  , ControlPlaneURL(..)
  , defaultConfig
    -- * Configuration Loading
  , loadConfig
  , saveConfig
  ) where

import Data.Text (Text)
import qualified Data.Text as T
import System.Directory (getHomeDirectory, createDirectoryIfMissing)
import System.FilePath ((</>))
import Network.Tailscale.Types (AuthKey, NodeKey)

-- | URL for the Tailscale control plane
newtype ControlPlaneURL = ControlPlaneURL Text
  deriving (Eq, Show)

-- | Configuration for Tailscale client
data Config = Config
  { configAuthKey :: !(Maybe AuthKey)
  , configNodeKey :: !(Maybe NodeKey)
  , configControlPlaneURL :: !ControlPlaneURL
  , configStatePath :: !FilePath
  , configHostname :: !(Maybe Text)
  } deriving (Eq, Show)

-- | Default configuration using official Tailscale control plane
defaultConfig :: Config
defaultConfig = Config
  { configAuthKey = Nothing
  , configNodeKey = Nothing
  , configControlPlaneURL = ControlPlaneURL "https://controlplane.tailscale.com"
  , configStatePath = ""  -- Will be set during initialization
  , configHostname = Nothing
  }

-- | Load configuration from disk
loadConfig :: IO Config
loadConfig = do
  homeDir <- getHomeDirectory
  let stateDir = homeDir </> ".tailscale"
  createDirectoryIfMissing True stateDir
  return defaultConfig { configStatePath = stateDir }

-- | Save configuration to disk
saveConfig :: Config -> IO ()
saveConfig _config = do
  -- In a full implementation, this would persist the config
  -- For now, we just ensure the state directory exists
  homeDir <- getHomeDirectory
  let stateDir = homeDir </> ".tailscale"
  createDirectoryIfMissing True stateDir
