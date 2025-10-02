package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// #############################################################################
// ## CONFIGURATION
// #############################################################################
// Fill out these details for your server and account.

var config = struct {
	LoginServerAddress string // IP:Port of the login server
	CharServerAddress  string // IP:Port of the character server
	MapServerAddress   string // This will be fetched automatically
	Username           string // Your account username (max 23 chars)
	Password           string // Your account password
	CharacterName      string // The exact name of the character to log in with
	ClientVersion      int32  // Server's client version (e.g., 20180620)
}{
	LoginServerAddress: "127.0.0.1:6900",
	CharServerAddress:  "127.0.0.1:6121",
	Username:           "myusername",
	Password:           "mypassword",
	CharacterName:      "MyLoggerChar",
	ClientVersion:      20180620,
}

// #############################################################################
// ## PACKET IDS & STRUCTURES
// #############################################################################

const (
	// Client -> Server Packet IDs
	packetLogin      = 0x0064
	packetCharSelect = 0x0066
	packetEnterMap   = 0x007d
	packetKeepAlive  = 0x0202 // Used to respond to server pings

	// Server -> Client Packet IDs
	packetAcceptLogin     = 0x0069
	packetCharList        = 0x006b
	packetMapServerInfo   = 0x006c
	packetMapLoginSuccess = 0x0073
	packetServerPing      = 0x008d
	packetBroadcast       = 0x009a
)

// Represents the login packet sent by the client.
type LoginPacket struct {
	PacketID    uint16
	Version     int32
	Username    [24]byte
	PasswordMD5 [16]byte
	ClientType  uint8
}

// Represents a character entry from the server's character list.
type CharacterEntry struct {
	CharID uint32
	// ... other fields we don't need for this logger
	_    [12]byte
	Name [24]byte
	// ... more fields we don't need
}

// #############################################################################
// ## CLIENT LOGIC
// #############################################################################

// Client holds the state and connection information.
type Client struct {
	conn       net.Conn
	accountID  uint32
	sessionID1 uint32
	sessionID2 uint32
	sex        byte
	charID     uint32
}

// NewClient creates a new client instance.
func NewClient() *Client {
	return &Client{}
}

// Run starts the entire connection and logging process.
func (c *Client) Run() {
	log.Println("Starting Ragnarok Logger...")

	if err := c.connectToLoginServer(); err != nil {
		log.Fatalf("Login server connection failed: %v", err)
	}

	if err := c.connectToCharServer(); err != nil {
		log.Fatalf("Character server connection failed: %v", err)
	}

	if err := c.connectToMapServer(); err != nil {
		log.Fatalf("Map server connection failed: %v", err)
	}

	log.Println("Successfully connected to map server. Listening for events...")
	c.listenForPackets()
}

// connectToLoginServer handles the authentication with the login server.
func (c *Client) connectToLoginServer() error {
	log.Printf("Connecting to Login Server at %s...", config.LoginServerAddress)
	conn, err := net.Dial("tcp", config.LoginServerAddress)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Create and send the login packet
	loginPkt := LoginPacket{
		PacketID:   packetLogin,
		Version:    config.ClientVersion,
		ClientType: 0,
	}
	copy(loginPkt.Username[:], config.Username)
	copy(loginPkt.PasswordMD5[:], md5.Sum([]byte(config.Password)))

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &loginPkt)
	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("could not send login packet: %v", err)
	}

	// Read the response from the login server
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("could not read login response header: %v", err)
	}

	packetID := binary.LittleEndian.Uint16(header)
	if packetID != packetAcceptLogin {
		// There are other failure packet IDs, but for simplicity we just check for success
		return fmt.Errorf("login failed. Received packet ID 0x%04x. Check username/password/version", packetID)
	}

	// Read the rest of the success packet
	response := make([]byte, 43) // Size of the 0x0069 packet body
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("could not read login success data: %v", err)
	}

	c.accountID = binary.LittleEndian.Uint32(response[2:6])
	c.sessionID1 = binary.LittleEndian.Uint32(response[6:10])
	c.sessionID2 = binary.LittleEndian.Uint32(response[10:14])
	c.sex = response[34]

	log.Printf("Login successful! Account ID: %d", c.accountID)
	return nil
}

// connectToCharServer handles character selection.
func (c *Client) connectToCharServer() error {
	log.Printf("Connecting to Character Server at %s...", config.CharServerAddress)
	conn, err := net.Dial("tcp", config.CharServerAddress)
	if err != nil {
		return err
	}
	defer conn.Close()
	c.conn = conn // Temporarily store connection for this stage

	// Send authentication packet to char server
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x0065)) // Packet ID
	binary.Write(buf, binary.LittleEndian, c.accountID)
	binary.Write(buf, binary.LittleEndian, c.sessionID1)
	binary.Write(buf, binary.LittleEndian, c.sessionID2)
	binary.Write(buf, binary.LittleEndian, c.sex)
	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("could not send char server auth: %v", err)
	}

	// Read packets until we get map server info or fail
	for {
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			return fmt.Errorf("char server connection closed: %v", err)
		}
		packetID := binary.LittleEndian.Uint16(header[0:2])
		packetLen := binary.LittleEndian.Uint16(header[2:4])
		body := make([]byte, packetLen-4)
		if _, err := io.ReadFull(conn, body); err != nil {
			return fmt.Errorf("could not read char packet body: %v", err)
		}

		switch packetID {
		case packetCharList:
			log.Println("Received character list.")
			foundChar := false
			// The character entries start after the header
			charEntries := body
			numChars := (len(charEntries)) / 155 // Each full char entry is 155 bytes

			for i := 0; i < numChars; i++ {
				offset := i * 155
				entryData := charEntries[offset : offset+155]

				nameBytes := entryData[20:44]
				charName := string(bytes.Trim(nameBytes, "\x00"))

				if charName == config.CharacterName {
					c.charID = binary.LittleEndian.Uint32(entryData[0:4])
					log.Printf("Found character '%s' with ID %d. Selecting...", charName, c.charID)

					// Send character selection packet
					selectBuf := new(bytes.Buffer)
					binary.Write(selectBuf, binary.LittleEndian, uint16(packetCharSelect))
					binary.Write(selectBuf, binary.LittleEndian, uint8(i)) // Char slot index
					conn.Write(selectBuf.Bytes())
					foundChar = true
					break
				}
			}

			if !foundChar {
				return fmt.Errorf("character '%s' not found on account", config.CharacterName)
			}

		case packetMapServerInfo:
			log.Println("Received map server information.")
			ipBytes := body[4:8]
			port := binary.LittleEndian.Uint16(body[8:10])
			mapIP := fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
			config.MapServerAddress = fmt.Sprintf("%s:%d", mapIP, port)
			log.Printf("Map Server located at: %s", config.MapServerAddress)
			return nil // Success!

		default:
			log.Printf("Received unhandled char server packet: 0x%04x", packetID)
		}
	}
}

// connectToMapServer connects to the final map server.
func (c *Client) connectToMapServer() error {
	log.Printf("Connecting to Map Server at %s...", config.MapServerAddress)
	conn, err := net.Dial("tcp", config.MapServerAddress)
	if err != nil {
		return err
	}
	c.conn = conn // This is our final, persistent connection

	// Send authentication to map server
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(packetEnterMap))
	binary.Write(buf, binary.LittleEndian, c.accountID)
	binary.Write(buf, binary.LittleEndian, c.charID)
	binary.Write(buf, binary.LittleEndian, c.sessionID1)
	binary.Write(buf, binary.LittleEndian, uint32(time.Now().Unix())) // Client tick
	binary.Write(buf, binary.LittleEndian, c.sex)
	_, err = c.conn.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("could not send map auth packet: %v", err)
	}

	// We expect a few packets, but we just need to confirm we're in.
	// We'll wait for the login success packet or timeout.
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{}) // Clear deadline after this function

	for {
		header := make([]byte, 2)
		if _, err := io.ReadFull(c.conn, header); err != nil {
			return fmt.Errorf("failed to read map server response: %v", err)
		}
		packetID := binary.LittleEndian.Uint16(header)
		if packetID == packetMapLoginSuccess {
			return nil // We are in!
		}
		// We need to discard other packets to find the one we want.
		// This is a simplification; a full client would parse packet lengths.
		// For now, we assume fixed small packets before success.
		dummy := make([]byte, 256) // Read and discard up to 256 bytes
		c.conn.Read(dummy)
	}
}

// listenForPackets is the main loop that reads and processes server messages.
func (c *Client) listenForPackets() {
	defer c.conn.Close()

	for {
		header := make([]byte, 4)
		if _, err := io.ReadFull(c.conn, header); err != nil {
			log.Printf("Connection closed by server: %v", err)
			return
		}

		packetID := binary.LittleEndian.Uint16(header[0:2])

		var packetLen int
		// Some packets have length in the header, some don't.
		// 0x009a (broadcast) does. 0x008d (ping) does not.
		if packetID == packetBroadcast {
			packetLen = int(binary.LittleEndian.Uint16(header[2:4]))
		}

		switch packetID {
		case packetBroadcast:
			if packetLen > 4 {
				body := make([]byte, packetLen-4)
				if _, err := io.ReadFull(c.conn, body); err != nil {
					log.Printf("Error reading broadcast body: %v", err)
					continue
				}
				message := string(body)
				handleBroadcast(message)
			}

		case packetServerPing:
			// The server is pinging us to check if we are still connected.
			// We MUST respond or we will be disconnected.
			// log.Println("Received server ping, sending keep-alive.")
			keepAliveBuf := new(bytes.Buffer)
			binary.Write(keepAliveBuf, binary.LittleEndian, uint16(packetKeepAlive))
			binary.Write(keepAliveBuf, binary.LittleEndian, c.accountID)
			c.conn.Write(keepAliveBuf.Bytes())

		default:
			// To prevent the stream from getting desynchronized on unknown packets,
			// we must attempt to read and discard them. This is a huge simplification
			// and the most likely point of failure on custom servers.
			// log.Printf("Ignoring unknown packet: 0x%04x", packetID)
		}
	}
}

// handleBroadcast processes messages and logs them if they match our criteria.
func handleBroadcast(message string) {
	// A server broadcast message often has a format like:
	// "ServerName : Message content here"
	// We clean it up for better logging.
	if parts := strings.SplitN(message, " : ", 2); len(parts) == 2 {
		message = parts[1]
	}

	// Check for keywords related to rare drops or MVPs
	lowerMsg := strings.ToLower(message)
	isRareDrop := strings.Contains(lowerMsg, "dropped") || strings.Contains(lowerMsg, "obtained a")
	isMVP := strings.Contains(lowerMsg, "mvp")

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	if isRareDrop || isMVP {
		log.Printf("[EVENT] %s | %s", timestamp, message)
	} else {
		// Log all other global messages
		log.Printf("[GLOBAL] %s | %s", timestamp, message)
	}
}

// #############################################################################
// ## MAIN FUNCTION
// #############################################################################

func main() {
	client := NewClient()
	client.Run()
}
