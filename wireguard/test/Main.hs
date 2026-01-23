{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Test.Tasty

import qualified CryptoSpec
import qualified InteropSpec
import qualified NoiseSpec
import qualified ProtocolSpec

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "WireGuard"
    [ CryptoSpec.tests
    , NoiseSpec.tests
    , ProtocolSpec.tests
    , InteropSpec.tests
    ]
