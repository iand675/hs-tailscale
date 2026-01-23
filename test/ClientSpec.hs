{-# LANGUAGE OverloadedStrings #-}

module ClientSpec (tests) where

import Test.Tasty
import Test.Tasty.HUnit

import Tailscale.Client

tests :: TestTree
tests =
  testGroup
    "Client"
    [ testGroup
        "URL encoding"
        [ testCase "urlEncodeText encodes special characters" $ do
            urlEncodeText "hello world" @?= "hello%20world"
            urlEncodeText "user@example.com" @?= "user@example.com" -- @ is valid in URLs
            urlEncodeText "a+b=c" @?= "a+b=c" -- + and = are valid in path segments
            urlEncodeText "simple" @?= "simple"
        , testCase "buildQueryString with empty params" $ do
            buildQueryString [] @?= ""
        , testCase "buildQueryString with single param" $ do
            buildQueryString [("key", "value")] @?= "?key=value"
        , testCase "buildQueryString with multiple params" $ do
            buildQueryString [("foo", "bar"), ("baz", "qux")]
              @?= "?foo=bar&baz=qux"
        , testCase "buildQueryString encodes special characters" $ do
            buildQueryString [("user", "john@example.com")]
              @?= "?user=john@example.com" -- @ is valid in query strings
            buildQueryString [("q", "hello world")]
              @?= "?q=hello%20world"
        , testCase "buildQueryString encodes keys and values" $ do
            buildQueryString [("my key", "my value")]
              @?= "?my%20key=my%20value"
        ]
    , testGroup
        "Constants"
        [ testCase "defaultBaseURL is correct" $ do
            defaultBaseURL @?= "https://api.tailscale.com"
        , testCase "maxResponseSize is 10MB" $ do
            maxResponseSize @?= 10485760
        ]
    ]
