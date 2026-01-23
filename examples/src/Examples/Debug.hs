{- |
Module      : Examples.Debug
Description : Debugging and logging utilities for examples
License     : BSD-3-Clause

This module provides utilities for creating examples with detailed
debugging output, making it easy to trace execution and understand
what's happening at each step.
-}
module Examples.Debug
  ( -- * Debug Output
    debugLn
  , debugShow
  , debugSection
  , debugStep
  , debugSubStep
  , debugSuccess
  , debugError
  , debugWarning
  , debugInfo
  , debugBytes
  , debugHex
  , debugJson
  , debugKeyValue
  , debugList
  , debugTable

    -- * Timing
  , timed
  , timedIO

    -- * Result Handling
  , debugResult
  , debugEither
  , debugMaybe

    -- * Color Codes (for terminals)
  , Color (..)
  , withColor
  , colored

    -- * Box Drawing
  , boxed
  , indented

    -- * Separators
  , separator
  , doubleSeparator
  ) where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Encode.Pretty as AesonPretty
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Lazy.Char8 as LBS
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock (diffUTCTime, getCurrentTime)
import System.IO (hFlush, stderr, stdout)
import Text.Printf (printf)


-- | ANSI color codes
data Color
  = Red
  | Green
  | Yellow
  | Blue
  | Magenta
  | Cyan
  | White
  | Reset
  deriving (Eq, Show)


-- | Get ANSI escape code for a color
colorCode :: Color -> String
colorCode Red = "\ESC[31m"
colorCode Green = "\ESC[32m"
colorCode Yellow = "\ESC[33m"
colorCode Blue = "\ESC[34m"
colorCode Magenta = "\ESC[35m"
colorCode Cyan = "\ESC[36m"
colorCode White = "\ESC[37m"
colorCode Reset = "\ESC[0m"


-- | Wrap a string with color codes
withColor :: Color -> String -> String
withColor color s = colorCode color ++ s ++ colorCode Reset


-- | Create a colored string
colored :: Color -> String -> String
colored = withColor


-- | Print a debug message
debugLn :: String -> IO ()
debugLn msg = do
  putStrLn msg
  hFlush stdout


-- | Print a value using Show
debugShow :: Show a => String -> a -> IO ()
debugShow label value = do
  putStrLn $ colored Cyan label ++ ": " ++ show value
  hFlush stdout


-- | Print a section header
debugSection :: String -> IO ()
debugSection title = do
  putStrLn ""
  putStrLn $ colored Blue "═══════════════════════════════════════════════════════════════════════════════"
  putStrLn $ colored Blue ("  " ++ title)
  putStrLn $ colored Blue "═══════════════════════════════════════════════════════════════════════════════"
  putStrLn ""
  hFlush stdout


-- | Print a step in a process
debugStep :: Int -> String -> IO ()
debugStep n desc = do
  putStrLn $ colored Yellow ("[Step " ++ show n ++ "] ") ++ desc
  hFlush stdout


-- | Print a sub-step
debugSubStep :: String -> IO ()
debugSubStep desc = do
  putStrLn $ "  " ++ colored Cyan "→ " ++ desc
  hFlush stdout


-- | Print a success message
debugSuccess :: String -> IO ()
debugSuccess msg = do
  putStrLn $ colored Green "✓ " ++ msg
  hFlush stdout


-- | Print an error message
debugError :: String -> IO ()
debugError msg = do
  putStrLn $ colored Red "✗ " ++ msg
  hFlush stdout


-- | Print a warning message
debugWarning :: String -> IO ()
debugWarning msg = do
  putStrLn $ colored Yellow "⚠ " ++ msg
  hFlush stdout


-- | Print an info message
debugInfo :: String -> IO ()
debugInfo msg = do
  putStrLn $ colored Cyan "ℹ " ++ msg
  hFlush stdout


-- | Print bytes in a readable format
debugBytes :: String -> ByteString -> IO ()
debugBytes label bs = do
  putStrLn $ colored Cyan label ++ ":"
  putStrLn $ "  Length: " ++ show (BS.length bs) ++ " bytes"
  putStrLn $ "  Hex:    " ++ take 64 (show (Base16.encode bs)) ++ if BS.length bs > 32 then "..." else ""
  hFlush stdout


-- | Print raw hex dump
debugHex :: String -> ByteString -> IO ()
debugHex label bs = do
  putStrLn $ colored Cyan label ++ " (" ++ show (BS.length bs) ++ " bytes):"
  let hex = TE.decodeUtf8 (Base16.encode bs)
      chunks = T.chunksOf 32 hex
  mapM_ (\(i, chunk) -> putStrLn $ printf "  %04x: %s" (i * 16 :: Int) (T.unpack chunk)) (zip [0..] chunks)
  hFlush stdout


-- | Print JSON data with pretty formatting
debugJson :: Aeson.ToJSON a => String -> a -> IO ()
debugJson label value = do
  putStrLn $ colored Cyan label ++ ":"
  LBS.putStrLn $ AesonPretty.encodePretty value
  hFlush stdout


-- | Print a key-value pair
debugKeyValue :: String -> String -> IO ()
debugKeyValue key value = do
  putStrLn $ "  " ++ colored Cyan (key ++ ":") ++ " " ++ value
  hFlush stdout


-- | Print a list of items
debugList :: Show a => String -> [a] -> IO ()
debugList label items = do
  putStrLn $ colored Cyan label ++ " (" ++ show (length items) ++ " items):"
  mapM_ (\(i, item) -> putStrLn $ printf "  [%d] %s" (i :: Int) (show item)) (zip [0..] items)
  hFlush stdout


-- | Print a table of key-value pairs
debugTable :: [(String, String)] -> IO ()
debugTable pairs = do
  let maxKeyLen = maximum (map (length . fst) pairs)
  mapM_ (\(k, v) -> putStrLn $ printf "  %-*s : %s" maxKeyLen k v) pairs
  hFlush stdout


-- | Time an IO action
timed :: String -> IO a -> IO a
timed label action = do
  putStr $ colored Cyan ("⏱ " ++ label ++ "... ")
  hFlush stdout
  start <- getCurrentTime
  result <- action
  end <- getCurrentTime
  let diff = diffUTCTime end start
  putStrLn $ colored Green ("done (" ++ show diff ++ ")")
  hFlush stdout
  return result


-- | Time an IO action and return the duration
timedIO :: IO a -> IO (a, Double)
timedIO action = do
  start <- getCurrentTime
  result <- action
  end <- getCurrentTime
  let diff = realToFrac (diffUTCTime end start) :: Double
  return (result, diff)


-- | Debug an Either result
debugEither :: Show e => String -> Either e a -> (a -> IO ()) -> IO ()
debugEither label result onSuccess = case result of
  Left err -> do
    debugError $ label ++ " failed:"
    putStrLn $ "  " ++ show err
    hFlush stdout
  Right val -> onSuccess val


-- | Debug a Maybe result
debugMaybe :: String -> Maybe a -> (a -> IO ()) -> IO ()
debugMaybe label result onSuccess = case result of
  Nothing -> do
    debugWarning $ label ++ " returned Nothing"
    hFlush stdout
  Just val -> onSuccess val


-- | Debug a result with success/failure indication
debugResult :: Show e => String -> Either e a -> (a -> String) -> IO ()
debugResult label result showVal = case result of
  Left err -> do
    debugError $ label ++ ":"
    putStrLn $ "  Error: " ++ show err
    hFlush stdout
  Right val -> do
    debugSuccess $ label ++ ":"
    putStrLn $ "  " ++ showVal val
    hFlush stdout


-- | Create a boxed output
boxed :: String -> [String] -> IO ()
boxed title lines' = do
  let maxLen = maximum (length title : map length lines')
      border = "┌─" ++ replicate maxLen '─' ++ "─┐"
      bottom = "└─" ++ replicate maxLen '─' ++ "─┘"
      pad s = s ++ replicate (maxLen - length s) ' '
  putStrLn border
  putStrLn $ "│ " ++ colored Cyan (pad title) ++ " │"
  putStrLn $ "├─" ++ replicate maxLen '─' ++ "─┤"
  mapM_ (\l -> putStrLn $ "│ " ++ pad l ++ " │") lines'
  putStrLn bottom
  hFlush stdout


-- | Create indented output
indented :: Int -> String -> String
indented n s = replicate n ' ' ++ s


-- | Print a separator line
separator :: IO ()
separator = do
  putStrLn $ colored Blue "───────────────────────────────────────────────────────────────────────────────"
  hFlush stdout


-- | Print a double separator line
doubleSeparator :: IO ()
doubleSeparator = do
  putStrLn $ colored Blue "═══════════════════════════════════════════════════════════════════════════════"
  hFlush stdout
