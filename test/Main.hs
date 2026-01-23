{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Test.Tasty
import Test.Tasty.HUnit

import qualified ClientSpec
import qualified CryptoSpec
import qualified TypesSpec

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests =
  testGroup
    "Tailscale"
    [ ClientSpec.tests
    , TypesSpec.tests
    , CryptoSpec.tests
    ]
