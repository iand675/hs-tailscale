{-# LANGUAGE MagicHash #-}

{- |
Module      : WireGuard.Bits
Description : Binary serialization utilities for WireGuard
License     : BSD-3-Clause

Little-endian byte serialization utilities used throughout the WireGuard
protocol implementation. Uses direct memory access for efficient operations.
-}
module WireGuard.Bits (
  -- * Reading
  getWord32LE,
  getWord64LE,

  -- * Writing
  putWord32LE,
  putWord64LE,
) where

import Data.Bits (byteSwap32, byteSwap64)
import Data.ByteString (ByteString)
import Data.ByteString.Internal (ByteString (..), unsafeCreate)
import Data.Word (Word32, Word64)
import Foreign.Ptr (Ptr, castPtr, plusPtr)
import Foreign.Storable (peek, poke)
import GHC.ByteOrder (ByteOrder (..), targetByteOrder)
import GHC.Exts (Ptr (..))
import GHC.ForeignPtr (ForeignPtr (..))
import System.IO.Unsafe (unsafeDupablePerformIO)

-- | Get a little-endian Word32 from a ByteString at the given offset.
-- Uses direct memory access for efficiency.
{-# INLINE getWord32LE #-}
getWord32LE :: ByteString -> Int -> Word32
getWord32LE (BS (ForeignPtr addr _) _) offset =
  unsafeDupablePerformIO $ do
    let ptr = Ptr addr `plusPtr` offset :: Ptr Word32
    w <- peek ptr
    return $! toLE32 w

-- | Get a little-endian Word64 from a ByteString at the given offset.
-- Uses direct memory access for efficiency.
{-# INLINE getWord64LE #-}
getWord64LE :: ByteString -> Int -> Word64
getWord64LE (BS (ForeignPtr addr _) _) offset =
  unsafeDupablePerformIO $ do
    let ptr = Ptr addr `plusPtr` offset :: Ptr Word64
    w <- peek ptr
    return $! toLE64 w

-- | Put a little-endian Word32 into a new ByteString.
-- Uses direct memory write for efficiency.
{-# INLINE putWord32LE #-}
putWord32LE :: Word32 -> ByteString
putWord32LE w = unsafeCreate 4 $ \ptr ->
  poke (castPtr ptr) (toLE32 w)

-- | Put a little-endian Word64 into a new ByteString.
-- Uses direct memory write for efficiency.
{-# INLINE putWord64LE #-}
putWord64LE :: Word64 -> ByteString
putWord64LE w = unsafeCreate 8 $ \ptr ->
  poke (castPtr ptr) (toLE64 w)

-- | Convert to/from little-endian (no-op on LE systems, byteswap on BE)
{-# INLINE toLE32 #-}
toLE32 :: Word32 -> Word32
toLE32 = case targetByteOrder of
  LittleEndian -> id
  BigEndian -> byteSwap32

{-# INLINE toLE64 #-}
toLE64 :: Word64 -> Word64
toLE64 = case targetByteOrder of
  LittleEndian -> id
  BigEndian -> byteSwap64
