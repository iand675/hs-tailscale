{- |
DERP (Detour Encrypted Relay Protocol) Example

This example demonstrates the DERP protocol used by Tailscale:
- Frame types and formats
- Frame parsing and serialization
- Protocol handshake flow
- Packet relay structure

Run with: cabal run derp-client-example
-}
module Main where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as Base16
import qualified Data.Text.Encoding as TE
import Data.Word (Word8)

import Examples.Debug
import Tsnet.DERP.Protocol
import WireGuard.Crypto


main :: IO ()
main = do
  debugSection "DERP Protocol Demo"

  debugInfo "DERP (Detour Encrypted Relay Protocol) is Tailscale's relay system."
  debugInfo "When direct peer-to-peer connections fail, traffic flows through DERP."
  debugInfo ""
  debugInfo "Frame format: Type (1 byte) | Length (4 bytes BE) | Payload"
  separator

  -- Step 1: Protocol Constants
  debugStep 1 "Protocol Constants"

  debugTable
    [ ("Protocol Version", show protocolVersion)
    , ("Max Frame Size", show maxFrameSize ++ " bytes (64 KB)")
    ]

  debugSubStep "Preferred DERP regions:"
  mapM_ printRegion preferredDERPRegions

  separator

  -- Step 2: Frame Types
  debugStep 2 "DERP Frame Types"

  debugInfo "DERP uses a simple binary framing protocol."

  boxed "Frame Types"
    [ "0x01 ServerKey     - Server sends its public key"
    , "0x02 ClientInfo    - Client sends version/capabilities"
    , "0x03 ServerInfo    - Server sends its info"
    , "0x04 SendPacket    - Client sends packet to peer"
    , "0x05 RecvPacket    - Server forwards packet from peer"
    , "0x06 KeepAlive     - Connection keepalive"
    , "0x07 NotePreferred - Client marks server as preferred"
    , "0x08 PeerGone      - Peer disconnected notification"
    , "0x09 PeerPresent   - Peer connected notification"
    , "0x0a WatchConns    - Request peer notifications"
    , "0x0b ClosePeer     - Close connection to peer"
    , "0x0c Ping          - Ping frame"
    , "0x0d Pong          - Pong frame (ping response)"
    , "0x0e Health        - Health check message"
    , "0x0f Restarting    - Server restarting notification"
    , "0x10 ForwardPacket - Packet with source info"
    ]

  separator

  -- Step 3: Frame Serialization
  debugStep 3 "Frame Serialization Examples"

  -- ServerKey frame
  debugSubStep "ServerKey frame (sent by server after connection):"
  let serverKey = ServerKey $ BS.replicate 32 0x42
      serverKeyFrame = serializeFrame (FServerKey serverKey)
  debugHex "Server Key" (unServerKey serverKey)
  debugHex "Serialized Frame" serverKeyFrame
  debugKeyValue "Frame breakdown" ""
  debugKeyValue "  Type" "0x01 (ServerKey)"
  debugKeyValue "  Length" "32 bytes"
  debugKeyValue "  Payload" "32-byte public key"

  separator

  -- ClientInfo frame
  debugSubStep "ClientInfo frame (sent by client after ServerKey):"
  let clientInfo = ClientInfo
        { ciVersion = protocolVersion
        , ciMeshKey = Nothing
        , ciCanAckPings = True
        , ciIsProber = False
        }
      clientInfoFrame = serializeFrame (FClientInfo clientInfo)
  debugTable
    [ ("Version", show $ ciVersion clientInfo)
    , ("Mesh Key", maybe "None" (const "Present") $ ciMeshKey clientInfo)
    , ("Can Ack Pings", show $ ciCanAckPings clientInfo)
    , ("Is Prober", show $ ciIsProber clientInfo)
    ]
  debugHex "Serialized Frame" clientInfoFrame

  separator

  -- SendPacket frame
  debugSubStep "SendPacket frame (client sending to peer via relay):"
  let destKey = BS.replicate 32 0xAB
      packetData = "Hello, peer!"
      sendPacket = SendPacket
        { spDestKey = destKey
        , spData = BS.pack $ map (fromIntegral . fromEnum) packetData
        }
      sendFrame = serializeFrame (FSendPacket sendPacket)
  debugHex "Destination Key" destKey
  debugKeyValue "Packet Data" packetData
  debugHex "Serialized Frame" sendFrame
  debugKeyValue "Frame breakdown" ""
  debugKeyValue "  Type" "0x04 (SendPacket)"
  debugKeyValue "  Length" (show (32 + length packetData) ++ " bytes")
  debugKeyValue "  Payload" "32-byte dest key + packet data"

  separator

  -- RecvPacket frame
  debugSubStep "RecvPacket frame (server forwarding from peer):"
  let srcKey = BS.replicate 32 0xCD
      recvPacket = RecvPacket
        { rpSourceKey = srcKey
        , rpData = BS.pack $ map (fromIntegral . fromEnum) "Hello from peer!"
        }
      recvFrame = serializeFrame (FRecvPacket recvPacket)
  debugHex "Source Key" srcKey
  debugHex "Serialized Frame" recvFrame

  separator

  -- Step 4: Frame Parsing
  debugStep 4 "Frame Parsing Examples"

  debugSubStep "Parsing ServerKey frame:"
  case parseFrame serverKeyFrame of
    Left err -> debugError $ "Parse error: " ++ err
    Right (frame, remaining) -> do
      debugSuccess "Frame parsed successfully"
      debugKeyValue "Frame Type" (show frame)
      debugKeyValue "Remaining Bytes" (show $ BS.length remaining)

  debugSubStep "Parsing SendPacket frame:"
  case parseFrame sendFrame of
    Left err -> debugError $ "Parse error: " ++ err
    Right (FSendPacket sp, remaining) -> do
      debugSuccess "Frame parsed successfully"
      debugHex "Destination Key" (spDestKey sp)
      debugKeyValue "Packet Length" (show $ BS.length $ spData sp)
      debugKeyValue "Remaining Bytes" (show $ BS.length remaining)
    Right (frame, _) -> debugError $ "Unexpected frame type: " ++ show frame

  separator

  -- Step 5: Handshake Flow
  debugStep 5 "DERP Handshake Flow"

  debugInfo "Connection establishment:"
  debugLn ""
  debugLn "  Client                         Server"
  debugLn "    |                               |"
  debugLn "    |  --- HTTP Upgrade Request --> |"
  debugLn "    |  <-- HTTP 101 Switching ----- |"
  debugLn "    |                               |"
  debugLn "    |  <----- ServerKey (0x01) ---- |  Server sends public key"
  debugLn "    |  ----- ClientInfo (0x02) --> |  Client sends version/caps"
  debugLn "    |  <---- ServerInfo (0x03) ---- |  Server sends its info"
  debugLn "    |                               |"
  debugLn "    |  [Connection established]     |"
  debugLn "    |                               |"
  debugLn "    |  ----- SendPacket (0x04) --> |  Client sends to peer"
  debugLn "    |  <---- RecvPacket (0x05) ---- |  Server forwards from peer"
  debugLn "    |                               |"

  separator

  -- Step 6: Ping/Pong
  debugStep 6 "Ping/Pong Keepalive"

  debugInfo "DERP uses ping/pong frames for connection health."

  let pingData = BS.pack [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
      pingFrame = serializeFrame (FPing $ Ping pingData)
      pongFrame = serializeFrame (FPong $ Pong pingData)

  debugSubStep "Ping frame:"
  debugHex "Ping Data (8 bytes)" pingData
  debugHex "Serialized Ping" pingFrame

  debugSubStep "Pong frame (echoes ping data):"
  debugHex "Serialized Pong" pongFrame

  separator

  -- Step 7: Peer Notifications
  debugStep 7 "Peer Presence Notifications"

  debugInfo "Clients can request notifications when peers connect/disconnect."

  let watchFrame = serializeFrame (FWatchConns WatchConns)
  debugSubStep "WatchConns frame (request notifications):"
  debugHex "Serialized Frame" watchFrame

  let peerKey = BS.replicate 32 0xEF
  let presentFrame = serializeFrame (FPeerPresent $ PeerPresent peerKey)
  let goneFrame = serializeFrame (FPeerGone $ PeerGone peerKey)

  debugSubStep "PeerPresent frame (peer connected):"
  debugHex "Peer Public Key" peerKey
  debugHex "Serialized Frame" presentFrame

  debugSubStep "PeerGone frame (peer disconnected):"
  debugHex "Serialized Frame" goneFrame

  separator

  -- Step 8: Server Restart
  debugStep 8 "Server Restart Notification"

  debugInfo "Servers notify clients before restarting."

  let restartFrame = serializeFrame (FRestarting $ Restarting
        { restartReconnectIn = 5000   -- 5 seconds
        , restartTryFor = 30000       -- 30 seconds
        })

  debugSubStep "Restarting frame:"
  debugTable
    [ ("Reconnect In", "5000 ms")
    , ("Try For", "30000 ms")
    ]
  debugHex "Serialized Frame" restartFrame

  separator

  -- Step 9: Health Messages
  debugStep 9 "Health Check Messages"

  let healthFrame = serializeFrame (FHealth $ Health "connection healthy")
  debugSubStep "Health frame:"
  debugKeyValue "Message" "connection healthy"
  debugHex "Serialized Frame" healthFrame

  separator

  -- Summary
  debugSection "DERP Protocol Summary"

  boxed "Key Features"
    [ "Binary framing   - Simple Type|Length|Payload format"
    , "Relay packets    - Forward encrypted WireGuard packets"
    , "Peer discovery   - Notify about peer connections"
    , "Keepalive        - Ping/pong for connection health"
    , "Graceful restart - Server restart notifications"
    , "HTTP upgrade     - Runs over HTTPS connection"
    ]

  debugTable
    [ ("Transport", "HTTPS (HTTP/1.1 upgrade)")
    , ("Port", "443")
    , ("Frame Header", "5 bytes (1 type + 4 length)")
    , ("Max Frame", "64 KB")
    , ("Key Size", "32 bytes (Curve25519)")
    ]

  debugSuccess "DERP protocol example completed!"


-- | Print DERP region info
printRegion :: (Int, T.Text, T.Text) -> IO ()
printRegion (regionId, code, name) = do
  debugKeyValue ("  " ++ show regionId ++ " (" ++ T.unpack code ++ ")")
                (T.unpack name)
