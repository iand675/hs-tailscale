{- |
IP Packet Parsing Example

This example demonstrates parsing IP packets:
- IPv4 header parsing
- IPv6 header parsing
- TCP/UDP protocol identification
- Packet construction for testing

Run with: cabal run packet-parsing-example
-}
module Main where

import Data.Bits ((.&.), (.|.), shiftL, shiftR)
import qualified Data.ByteString as BS
import Data.Word (Word8, Word16, Word32)

import Examples.Debug
import Tsnet.Network.Packet


main :: IO ()
main = do
  debugSection "IP Packet Parsing Demo"

  debugInfo "Understanding IP packet structure is essential for"
  debugInfo "implementing WireGuard and Tailscale networking."
  separator

  -- Step 1: IPv4 Header Structure
  debugStep 1 "IPv4 Header Structure"

  debugLn "IPv4 Header (20 bytes minimum):"
  debugLn ""
  debugLn "   0                   1                   2                   3"
  debugLn "   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1"
  debugLn "  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  debugLn "  |Version|  IHL  |Type of Service|          Total Length         |"
  debugLn "  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  debugLn "  |         Identification        |Flags|      Fragment Offset    |"
  debugLn "  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  debugLn "  |  Time to Live |    Protocol   |         Header Checksum       |"
  debugLn "  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  debugLn "  |                       Source Address                          |"
  debugLn "  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  debugLn "  |                    Destination Address                        |"
  debugLn "  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  debugLn "  |                    Options (if IHL > 5)                       |"
  debugLn "  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"

  separator

  -- Step 2: Create Sample IPv4 Packet
  debugStep 2 "Creating Sample IPv4 Packet"

  let srcIP = (100, 64, 0, 1)      -- Tailscale CGNAT range
      dstIP = (100, 64, 0, 2)
      srcPort = 12345 :: Word16
      dstPort = 80 :: Word16
      payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

  debugSubStep "Packet parameters:"
  debugTable
    [ ("Source IP", formatIPv4 srcIP)
    , ("Destination IP", formatIPv4 dstIP)
    , ("Source Port", show srcPort)
    , ("Destination Port", show dstPort)
    , ("Protocol", "TCP (6)")
    , ("Payload Size", show (length payload) ++ " bytes")
    ]

  let ipv4Packet = createIPv4TCPPacket srcIP dstIP srcPort dstPort payload

  debugSubStep "Raw packet bytes:"
  debugHex "IPv4+TCP Packet" ipv4Packet

  separator

  -- Step 3: Parse IPv4 Packet
  debugStep 3 "Parsing IPv4 Packet"

  case parseIPv4Header ipv4Packet of
    Nothing -> debugError "Failed to parse IPv4 header"
    Just info -> do
      debugSuccess "IPv4 header parsed successfully"
      debugSubStep "Header fields:"
      debugTable
        [ ("Version", show $ ipVersion info)
        , ("Header Length", show (ipHeaderLen info) ++ " bytes")
        , ("Total Length", show (ipTotalLen info) ++ " bytes")
        , ("Protocol", protocolName (ipProtocol info))
        , ("TTL", show $ ipTTL info)
        , ("Source IP", formatIPv4Bytes $ ipSrcAddr info)
        , ("Dest IP", formatIPv4Bytes $ ipDstAddr info)
        ]

      -- Parse TCP header if present
      when (ipProtocol info == 6) $ do
        let tcpData = BS.drop (ipHeaderLen info) ipv4Packet
        case parseTCPHeader tcpData of
          Nothing -> debugWarning "Failed to parse TCP header"
          Just tcp -> do
            debugSubStep "TCP header fields:"
            debugTable
              [ ("Source Port", show $ tcpSrcPort tcp)
              , ("Dest Port", show $ tcpDstPort tcp)
              , ("Sequence", show $ tcpSeqNum tcp)
              , ("Ack Number", show $ tcpAckNum tcp)
              , ("Flags", formatTCPFlags $ tcpFlags tcp)
              , ("Window", show $ tcpWindow tcp)
              ]

  separator

  -- Step 4: IPv6 Header Structure
  debugStep 4 "IPv6 Header Structure"

  debugLn "IPv6 Header (40 bytes fixed):"
  debugLn ""
  debugLn "   0                   1                   2                   3"
  debugLn "   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1"
  debugLn "  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  debugLn "  |Version| Traffic Class |           Flow Label                  |"
  debugLn "  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  debugLn "  |         Payload Length        |  Next Header  |   Hop Limit   |"
  debugLn "  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  debugLn "  |                                                               |"
  debugLn "  +                         Source Address                        +"
  debugLn "  |                         (128 bits)                            |"
  debugLn "  +                                                               +"
  debugLn "  |                                                               |"
  debugLn "  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"
  debugLn "  |                                                               |"
  debugLn "  +                      Destination Address                      +"
  debugLn "  |                         (128 bits)                            |"
  debugLn "  +                                                               +"
  debugLn "  |                                                               |"
  debugLn "  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"

  separator

  -- Step 5: Create Sample IPv6 Packet
  debugStep 5 "Creating Sample IPv6 Packet"

  let srcIPv6 = BS.pack [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
      dstIPv6 = BS.pack [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]

  debugSubStep "Packet parameters:"
  debugTable
    [ ("Source IPv6", formatIPv6 srcIPv6)
    , ("Dest IPv6", formatIPv6 dstIPv6)
    , ("Next Header", "UDP (17)")
    , ("Payload", "DNS query")
    ]

  let ipv6Packet = createIPv6UDPPacket srcIPv6 dstIPv6 53 53 "DNS query"

  debugSubStep "Raw packet bytes:"
  debugHex "IPv6+UDP Packet" ipv6Packet

  separator

  -- Step 6: Parse IPv6 Packet
  debugStep 6 "Parsing IPv6 Packet"

  case parseIPv6Header ipv6Packet of
    Nothing -> debugError "Failed to parse IPv6 header"
    Just info -> do
      debugSuccess "IPv6 header parsed successfully"
      debugSubStep "Header fields:"
      debugTable
        [ ("Version", show $ ip6Version info)
        , ("Traffic Class", show $ ip6TrafficClass info)
        , ("Flow Label", show $ ip6FlowLabel info)
        , ("Payload Length", show (ip6PayloadLen info) ++ " bytes")
        , ("Next Header", protocolName $ ip6NextHeader info)
        , ("Hop Limit", show $ ip6HopLimit info)
        , ("Source IP", formatIPv6 $ ip6SrcAddr info)
        , ("Dest IP", formatIPv6 $ ip6DstAddr info)
        ]

  separator

  -- Step 7: Protocol Numbers
  debugStep 7 "Common Protocol Numbers"

  boxed "IP Protocol Numbers"
    [ "  1  ICMP   - Internet Control Message Protocol"
    , "  6  TCP    - Transmission Control Protocol"
    , " 17  UDP    - User Datagram Protocol"
    , " 41  IPv6   - IPv6 encapsulation"
    , " 47  GRE    - Generic Routing Encapsulation"
    , " 50  ESP    - Encapsulating Security Payload"
    , " 51  AH     - Authentication Header"
    , " 58  ICMPv6 - ICMP for IPv6"
    ]

  separator

  -- Step 8: Tailscale CGNAT Range
  debugStep 8 "Tailscale IP Ranges"

  debugInfo "Tailscale uses specific IP ranges for its network:"

  debugTable
    [ ("IPv4 CGNAT", "100.64.0.0/10")
    , ("IPv6 ULA", "fd7a:115c:a1e0::/48")
    , ("MagicDNS", "100.100.100.100")
    ]

  debugSubStep "CGNAT range breakdown:"
  debugTable
    [ ("Start", "100.64.0.0")
    , ("End", "100.127.255.255")
    , ("Total IPs", "4,194,304 addresses")
    ]

  separator

  -- Summary
  debugSection "Packet Parsing Summary"

  boxed "Packet Processing Capabilities"
    [ "✓ IPv4 header parsing"
    , "✓ IPv6 header parsing"
    , "✓ TCP header parsing"
    , "✓ UDP header parsing"
    , "✓ Protocol identification"
    , "✓ Address extraction"
    ]

  debugSuccess "Packet parsing example completed!"


-- | IPv4 header info
data IPv4Info = IPv4Info
  { ipVersion :: Word8
  , ipHeaderLen :: Int
  , ipTotalLen :: Int
  , ipProtocol :: Word8
  , ipTTL :: Word8
  , ipSrcAddr :: BS.ByteString
  , ipDstAddr :: BS.ByteString
  }

-- | Parse IPv4 header
parseIPv4Header :: BS.ByteString -> Maybe IPv4Info
parseIPv4Header bs
  | BS.length bs < 20 = Nothing
  | otherwise =
      let version = (BS.index bs 0 `shiftR` 4) .&. 0x0F
          ihl = fromIntegral $ (BS.index bs 0 .&. 0x0F) * 4
          totalLen = fromIntegral (BS.index bs 2) `shiftL` 8 .|. fromIntegral (BS.index bs 3)
          protocol = BS.index bs 9
          ttl = BS.index bs 8
          srcAddr = BS.take 4 $ BS.drop 12 bs
          dstAddr = BS.take 4 $ BS.drop 16 bs
      in if version == 4
         then Just IPv4Info
           { ipVersion = version
           , ipHeaderLen = ihl
           , ipTotalLen = totalLen
           , ipProtocol = protocol
           , ipTTL = ttl
           , ipSrcAddr = srcAddr
           , ipDstAddr = dstAddr
           }
         else Nothing

-- | IPv6 header info
data IPv6Info = IPv6Info
  { ip6Version :: Word8
  , ip6TrafficClass :: Word8
  , ip6FlowLabel :: Word32
  , ip6PayloadLen :: Int
  , ip6NextHeader :: Word8
  , ip6HopLimit :: Word8
  , ip6SrcAddr :: BS.ByteString
  , ip6DstAddr :: BS.ByteString
  }

-- | Parse IPv6 header
parseIPv6Header :: BS.ByteString -> Maybe IPv6Info
parseIPv6Header bs
  | BS.length bs < 40 = Nothing
  | otherwise =
      let b0 = BS.index bs 0
          version = (b0 `shiftR` 4) .&. 0x0F
          trafficClass = ((b0 .&. 0x0F) `shiftL` 4) .|. ((BS.index bs 1 `shiftR` 4) .&. 0x0F)
          flowLabel = (fromIntegral (BS.index bs 1 .&. 0x0F) `shiftL` 16) .|.
                      (fromIntegral (BS.index bs 2) `shiftL` 8) .|.
                      fromIntegral (BS.index bs 3)
          payloadLen = fromIntegral (BS.index bs 4) `shiftL` 8 .|. fromIntegral (BS.index bs 5)
          nextHeader = BS.index bs 6
          hopLimit = BS.index bs 7
          srcAddr = BS.take 16 $ BS.drop 8 bs
          dstAddr = BS.take 16 $ BS.drop 24 bs
      in if version == 6
         then Just IPv6Info
           { ip6Version = version
           , ip6TrafficClass = trafficClass
           , ip6FlowLabel = flowLabel
           , ip6PayloadLen = payloadLen
           , ip6NextHeader = nextHeader
           , ip6HopLimit = hopLimit
           , ip6SrcAddr = srcAddr
           , ip6DstAddr = dstAddr
           }
         else Nothing

-- | TCP header info
data TCPInfo = TCPInfo
  { tcpSrcPort :: Word16
  , tcpDstPort :: Word16
  , tcpSeqNum :: Word32
  , tcpAckNum :: Word32
  , tcpFlags :: Word8
  , tcpWindow :: Word16
  }

-- | Parse TCP header
parseTCPHeader :: BS.ByteString -> Maybe TCPInfo
parseTCPHeader bs
  | BS.length bs < 20 = Nothing
  | otherwise =
      let srcPort = fromIntegral (BS.index bs 0) `shiftL` 8 .|. fromIntegral (BS.index bs 1)
          dstPort = fromIntegral (BS.index bs 2) `shiftL` 8 .|. fromIntegral (BS.index bs 3)
          seqNum = fromIntegral (BS.index bs 4) `shiftL` 24 .|.
                   fromIntegral (BS.index bs 5) `shiftL` 16 .|.
                   fromIntegral (BS.index bs 6) `shiftL` 8 .|.
                   fromIntegral (BS.index bs 7)
          ackNum = fromIntegral (BS.index bs 8) `shiftL` 24 .|.
                   fromIntegral (BS.index bs 9) `shiftL` 16 .|.
                   fromIntegral (BS.index bs 10) `shiftL` 8 .|.
                   fromIntegral (BS.index bs 11)
          flags = BS.index bs 13
          window = fromIntegral (BS.index bs 14) `shiftL` 8 .|. fromIntegral (BS.index bs 15)
      in Just TCPInfo
        { tcpSrcPort = srcPort
        , tcpDstPort = dstPort
        , tcpSeqNum = seqNum
        , tcpAckNum = ackNum
        , tcpFlags = flags
        , tcpWindow = window
        }

-- | Create IPv4 TCP packet
createIPv4TCPPacket :: (Word8, Word8, Word8, Word8)
                    -> (Word8, Word8, Word8, Word8)
                    -> Word16 -> Word16 -> String -> BS.ByteString
createIPv4TCPPacket (s1,s2,s3,s4) (d1,d2,d3,d4) srcPort dstPort payload =
  let payloadBytes = BS.pack $ map (fromIntegral . fromEnum) payload
      tcpLen = 20 + BS.length payloadBytes
      totalLen = 20 + tcpLen

      -- IPv4 header
      ipHeader = BS.pack
        [ 0x45  -- Version 4, IHL 5
        , 0x00  -- TOS
        , fromIntegral (totalLen `shiftR` 8), fromIntegral (totalLen .&. 0xFF)
        , 0x00, 0x00  -- Identification
        , 0x40, 0x00  -- Flags (Don't Fragment), Fragment Offset
        , 0x40  -- TTL
        , 0x06  -- Protocol (TCP)
        , 0x00, 0x00  -- Checksum (placeholder)
        , s1, s2, s3, s4  -- Source
        , d1, d2, d3, d4  -- Destination
        ]

      -- TCP header
      tcpHeader = BS.pack
        [ fromIntegral (srcPort `shiftR` 8), fromIntegral (srcPort .&. 0xFF)
        , fromIntegral (dstPort `shiftR` 8), fromIntegral (dstPort .&. 0xFF)
        , 0x00, 0x00, 0x00, 0x01  -- Sequence number
        , 0x00, 0x00, 0x00, 0x00  -- Ack number
        , 0x50  -- Data offset (5 * 4 = 20 bytes)
        , 0x02  -- Flags (SYN)
        , 0xFF, 0xFF  -- Window size
        , 0x00, 0x00  -- Checksum (placeholder)
        , 0x00, 0x00  -- Urgent pointer
        ]

  in ipHeader <> tcpHeader <> payloadBytes

-- | Create IPv6 UDP packet
createIPv6UDPPacket :: BS.ByteString -> BS.ByteString -> Word16 -> Word16 -> String -> BS.ByteString
createIPv6UDPPacket srcIPv6 dstIPv6 srcPort dstPort payload =
  let payloadBytes = BS.pack $ map (fromIntegral . fromEnum) payload
      udpLen = 8 + BS.length payloadBytes

      -- IPv6 header
      ipv6Header = BS.pack
        [ 0x60, 0x00, 0x00, 0x00  -- Version, TC, Flow Label
        , fromIntegral (udpLen `shiftR` 8), fromIntegral (udpLen .&. 0xFF)  -- Payload length
        , 17  -- Next header (UDP)
        , 64  -- Hop limit
        ] <> srcIPv6 <> dstIPv6

      -- UDP header
      udpHeader = BS.pack
        [ fromIntegral (srcPort `shiftR` 8), fromIntegral (srcPort .&. 0xFF)
        , fromIntegral (dstPort `shiftR` 8), fromIntegral (dstPort .&. 0xFF)
        , fromIntegral (udpLen `shiftR` 8), fromIntegral (udpLen .&. 0xFF)
        , 0x00, 0x00  -- Checksum (placeholder)
        ]

  in ipv6Header <> udpHeader <> payloadBytes

-- | Format IPv4 address
formatIPv4 :: (Word8, Word8, Word8, Word8) -> String
formatIPv4 (a, b, c, d) = show a ++ "." ++ show b ++ "." ++ show c ++ "." ++ show d

-- | Format IPv4 from bytes
formatIPv4Bytes :: BS.ByteString -> String
formatIPv4Bytes bs
  | BS.length bs < 4 = "Invalid"
  | otherwise = formatIPv4 (BS.index bs 0, BS.index bs 1, BS.index bs 2, BS.index bs 3)

-- | Format IPv6 address
formatIPv6 :: BS.ByteString -> String
formatIPv6 bs
  | BS.length bs /= 16 = "Invalid"
  | otherwise =
      let pairs = zip [0,2..14] [2,4..16]
          hexPairs = map (\(i, j) ->
            let b1 = BS.index bs i
                b2 = BS.index bs (i+1)
            in hexWord16 (fromIntegral b1 `shiftL` 8 .|. fromIntegral b2)
            ) [(0,0), (2,0), (4,0), (6,0), (8,0), (10,0), (12,0), (14,0)]
      in concatMap (++":") (init hexPairs) ++ last hexPairs
  where
    hexWord16 :: Word16 -> String
    hexWord16 w = hexDigit (fromIntegral $ (w `shiftR` 12) .&. 0xF) :
                  hexDigit (fromIntegral $ (w `shiftR` 8) .&. 0xF) :
                  hexDigit (fromIntegral $ (w `shiftR` 4) .&. 0xF) :
                  hexDigit (fromIntegral $ w .&. 0xF) : []
    hexDigit n | n < 10 = toEnum (fromEnum '0' + n)
               | otherwise = toEnum (fromEnum 'a' + n - 10)

-- | Protocol name
protocolName :: Word8 -> String
protocolName 1 = "ICMP (1)"
protocolName 6 = "TCP (6)"
protocolName 17 = "UDP (17)"
protocolName 58 = "ICMPv6 (58)"
protocolName n = "Unknown (" ++ show n ++ ")"

-- | Format TCP flags
formatTCPFlags :: Word8 -> String
formatTCPFlags f =
  let flags = [ (0x01, "FIN")
              , (0x02, "SYN")
              , (0x04, "RST")
              , (0x08, "PSH")
              , (0x10, "ACK")
              , (0x20, "URG")
              ]
      active = [name | (mask, name) <- flags, f .&. mask /= 0]
  in if null active then "None" else unwords active

-- | Helper
when :: Bool -> IO () -> IO ()
when True action = action
when False _ = return ()
