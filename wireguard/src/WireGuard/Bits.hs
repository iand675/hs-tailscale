{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : WireGuard.Bits
Description : Binary serialization utilities for WireGuard
License     : BSD-3-Clause

Little-endian byte serialization utilities used throughout the WireGuard
protocol implementation.
-}
module WireGuard.Bits (
  -- * Reading
  getWord32LE,
  getWord64LE,

  -- * Writing
  putWord32LE,
  putWord64LE,
) where

import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word32, Word64)

-- | Get a little-endian Word32 from a ByteString at the given offset
getWord32LE :: ByteString -> Int -> Word32
getWord32LE bs offset =
  let b0 = fromIntegral $ BS.index bs offset
      b1 = fromIntegral $ BS.index bs (offset + 1)
      b2 = fromIntegral $ BS.index bs (offset + 2)
      b3 = fromIntegral $ BS.index bs (offset + 3)
   in b0 .|. (b1 `shiftL` 8) .|. (b2 `shiftL` 16) .|. (b3 `shiftL` 24)

-- | Get a little-endian Word64 from a ByteString at the given offset
getWord64LE :: ByteString -> Int -> Word64
getWord64LE bs offset =
  let b0 = fromIntegral $ BS.index bs offset
      b1 = fromIntegral $ BS.index bs (offset + 1)
      b2 = fromIntegral $ BS.index bs (offset + 2)
      b3 = fromIntegral $ BS.index bs (offset + 3)
      b4 = fromIntegral $ BS.index bs (offset + 4)
      b5 = fromIntegral $ BS.index bs (offset + 5)
      b6 = fromIntegral $ BS.index bs (offset + 6)
      b7 = fromIntegral $ BS.index bs (offset + 7)
   in b0
        .|. (b1 `shiftL` 8)
        .|. (b2 `shiftL` 16)
        .|. (b3 `shiftL` 24)
        .|. (b4 `shiftL` 32)
        .|. (b5 `shiftL` 40)
        .|. (b6 `shiftL` 48)
        .|. (b7 `shiftL` 56)

-- | Put a little-endian Word32
putWord32LE :: Word32 -> ByteString
putWord32LE w =
  BS.pack
    [ fromIntegral (w .&. 0xFF)
    , fromIntegral ((w `shiftR` 8) .&. 0xFF)
    , fromIntegral ((w `shiftR` 16) .&. 0xFF)
    , fromIntegral ((w `shiftR` 24) .&. 0xFF)
    ]

-- | Put a little-endian Word64
putWord64LE :: Word64 -> ByteString
putWord64LE w =
  BS.pack
    [ fromIntegral (w .&. 0xFF)
    , fromIntegral ((w `shiftR` 8) .&. 0xFF)
    , fromIntegral ((w `shiftR` 16) .&. 0xFF)
    , fromIntegral ((w `shiftR` 24) .&. 0xFF)
    , fromIntegral ((w `shiftR` 32) .&. 0xFF)
    , fromIntegral ((w `shiftR` 40) .&. 0xFF)
    , fromIntegral ((w `shiftR` 48) .&. 0xFF)
    , fromIntegral ((w `shiftR` 56) .&. 0xFF)
    ]
