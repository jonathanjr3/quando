package server

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

type PairingState int

const (
	WaitingForClient PairingState = iota // The /join page is open, but client hasn't clicked "Pair"
	ReadyForSAS                          // Client clicked "Pair", SAS is generated and displayed
	Paired                               // Handshake complete, client is connected
	Expired                              // Session timed out
)

type PairingSession struct {
	ID          string
	State       PairingState
	SAS         string
	DisplayConn *websocket.Conn // WebSocket for the /join page (the public screen)
	ClientConn  *websocket.Conn // WebSocket for the /pair page (the user's device)
	ExpiryTimer *time.Timer
	CreatedAt   time.Time

	// Cryptographic fields for P-256 ECDH
	ServerPrivateKey []byte // P-256 private key
	ServerPublicKey  []byte // P-256 public key
	ClientPublicKey  []byte // Client's P-256 public key
	SharedSecret     []byte // ECDH shared secret
	CryptoSAS        string // Cryptographically derived SAS

	// Rate limiting fields
	AttemptCount     int
	LastAttempt      time.Time
	NextAttemptAfter time.Time
}

// SessionManager safely handles concurrent access to pairing sessions
type SessionManager struct {
	sessions map[string]*PairingSession
	mu       sync.RWMutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*PairingSession),
	}
}

// GenerateRandomID creates a URL-safe random string for session IDs
func GenerateRandomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// generateP256KeyPair generates a new P-256 ECDH key pair
func generateP256KeyPair() ([]byte, []byte, error) {
	// Use P-256 curve for broader browser compatibility
	curve := ecdh.P256()

	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	publicKeyBytes := privateKey.PublicKey().Bytes()
	privateKeyBytes := privateKey.Bytes()

	return privateKeyBytes, publicKeyBytes, nil
}

// computeSharedSecret performs P-256 ECDH to compute shared secret
func computeSharedSecret(privateKeyBytes, clientPublicKeyBytes []byte) ([]byte, error) {
	curve := ecdh.P256()

	// Import private key
	privateKey, err := curve.NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	// Import client public key
	clientPublicKey, err := curve.NewPublicKey(clientPublicKeyBytes)
	if err != nil {
		return nil, err
	}

	// Perform ECDH
	sharedSecret, err := privateKey.ECDH(clientPublicKey)
	if err != nil {
		return nil, err
	}

	return sharedSecret, nil
}

// deriveCryptoSAS derives a 6-digit SAS from shared secret using HMAC-SHA256
func deriveCryptoSAS(sharedSecret []byte) string {
	// Create HMAC-SHA256 with shared secret as key
	h := hmac.New(sha256.New, sharedSecret)
	h.Write([]byte("SAS_DERIVATION"))
	mac := h.Sum(nil)

	// Take first 4 bytes and convert to uint32
	sasValue := binary.BigEndian.Uint32(mac[:4])

	// Truncate to 20 bits (1048576 values) and map to 6-digit range
	sasValue = sasValue & 0xFFFFF           // 20 bits
	sasValue = (sasValue % 900000) + 100000 // Map to 100000-999999

	return fmt.Sprintf("%06d", sasValue)
}

// authenticateMessage creates HMAC for a message
func authenticateMessage(sharedSecret []byte, message []byte) string {
	h := hmac.New(sha256.New, sharedSecret)
	h.Write(message)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// verifyMessageAuthentication verifies HMAC of a message
func verifyMessageAuthentication(sharedSecret []byte, message []byte, expectedHMAC string) bool {
	expectedBytes, err := base64.StdEncoding.DecodeString(expectedHMAC)
	if err != nil {
		return false
	}

	h := hmac.New(sha256.New, sharedSecret)
	h.Write(message)
	computedMAC := h.Sum(nil)

	return hmac.Equal(computedMAC, expectedBytes)
}

// ValidateToken checks if a pairing token is valid and authenticated
func (sm *SessionManager) ValidateToken(token string) bool {
	fmt.Printf("DEBUG: Validating authenticated token\n")

	if !strings.HasPrefix(token, "TOKEN_") {
		fmt.Printf("DEBUG: Token doesn't start with TOKEN_\n")
		return false
	}

	// Split token into data and HMAC parts
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		fmt.Printf("DEBUG: Token doesn't have HMAC part\n")
		return false
	}

	tokenData := parts[0]
	tokenHMAC := parts[1]

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Extract session ID from token data (format: TOKEN_{sessionID}_{timestamp})
	tokenParts := strings.Split(tokenData, "_")
	if len(tokenParts) < 3 {
		fmt.Printf("DEBUG: Token data doesn't have enough parts: %d\n", len(tokenParts))
		return false
	}

	sessionID := tokenParts[1]
	fmt.Printf("DEBUG: Extracted session ID: %s\n", sessionID)

	session, exists := sm.sessions[sessionID]
	if !exists {
		fmt.Printf("DEBUG: Session %s not found\n", sessionID)
		return false
	}

	// Check if session is in Paired state
	if session.State != Paired {
		fmt.Printf("DEBUG: Session not in Paired state: %v\n", session.State)
		return false
	}

	// Verify token HMAC
	if !verifyMessageAuthentication(session.SharedSecret, []byte(tokenData), tokenHMAC) {
		fmt.Printf("DEBUG: Token HMAC verification failed\n")
		return false
	}

	fmt.Printf("DEBUG: Token validation successful\n")
	return true
}

// InvalidateSession removes a session from the manager
func (sm *SessionManager) InvalidateSession(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, exists := sm.sessions[sessionID]; exists {
		// Close any WebSocket connections
		if session.DisplayConn != nil {
			displayMsg := map[string]string{
				"type": "session_invalidated",
			}
			websocket.JSON.Send(session.DisplayConn, displayMsg)
		}
		if session.ClientConn != nil {
			clientMsg := map[string]string{
				"type": "session_invalidated",
			}
			websocket.JSON.Send(session.ClientConn, clientMsg)
		}

		delete(sm.sessions, sessionID)
		fmt.Printf("Session %s invalidated\n", sessionID)
	}
}

// InvalidateTokenSession invalidates a session based on token
func (sm *SessionManager) InvalidateTokenSession(token string) bool {
	if !strings.HasPrefix(token, "TOKEN_") {
		return false
	}

	parts := strings.Split(token, "_")
	if len(parts) < 3 {
		return false
	}

	sessionID := parts[1]
	sm.InvalidateSession(sessionID)
	return true
}

// CreateSession creates a new pairing session
func (sm *SessionManager) CreateSession(sessionID string) *PairingSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Generate P-256 ECDH key pair for this session
	privateKey, publicKey, err := generateP256KeyPair()
	if err != nil {
		fmt.Printf("Failed to generate key pair for session %s: %v\n", sessionID, err)
		return nil
	}

	session := &PairingSession{
		ID:               sessionID,
		State:            WaitingForClient,
		CreatedAt:        time.Now(),
		ServerPrivateKey: privateKey,
		ServerPublicKey:  publicKey,
		AttemptCount:     0,
	}
	sm.sessions[sessionID] = session

	// Set up automatic cleanup after 30 minutes
	session.ExpiryTimer = time.AfterFunc(30*time.Minute, func() {
		sm.CleanupSession(sessionID)
	})

	fmt.Printf("Created session %s with public key: %s\n", sessionID,
		base64.StdEncoding.EncodeToString(publicKey))

	return session
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*PairingSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	session, exists := sm.sessions[sessionID]
	return session, exists
}

// GetSessionByToken performs a light parse to locate the session without verifying the HMAC.
// Callers should validate tokens separately before trusting the result.
func (sm *SessionManager) GetSessionByToken(token string) (*PairingSession, bool) {
	parts := strings.Split(token, "_")
	if len(parts) < 3 {
		return nil, false
	}
	sessionID := parts[1]
	return sm.GetSession(sessionID)
}

// GetSessionInfo returns session information for QR code generation
func (sm *SessionManager) GetSessionInfo(sessionID string) (map[string]interface{}, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, false
	}

	return map[string]interface{}{
		"sessionId":       sessionID,
		"serverPublicKey": base64.StdEncoding.EncodeToString(session.ServerPublicKey),
	}, true
}

// CleanupSession removes a session and closes its connections
func (sm *SessionManager) CleanupSession(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, exists := sm.sessions[sessionID]; exists {
		if session.DisplayConn != nil {
			session.DisplayConn.Close()
		}
		if session.ClientConn != nil {
			session.ClientConn.Close()
		}
		if session.ExpiryTimer != nil {
			session.ExpiryTimer.Stop()
		}
		delete(sm.sessions, sessionID)
	}
}

// UpdateSessionState updates the state of a session
func (sm *SessionManager) UpdateSessionState(sessionID string, state PairingState) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if session, exists := sm.sessions[sessionID]; exists {
		session.State = state
	}
}

// SetSessionConnections sets the WebSocket connections for a session
func (sm *SessionManager) SetDisplayConnection(sessionID string, conn *websocket.Conn) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if session, exists := sm.sessions[sessionID]; exists {
		session.DisplayConn = conn
	}
}

func (sm *SessionManager) SetClientConnection(sessionID string, conn *websocket.Conn) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if session, exists := sm.sessions[sessionID]; exists {
		session.ClientConn = conn
	}
}

// HandlePairingWebSocket manages the WebSocket connections for the pairing process
func HandlePairingWebSocket(sm *SessionManager) func(ws *websocket.Conn) {
	return func(ws *websocket.Conn) {
		defer ws.Close()

		// Read the initial registration message
		var initialMsg map[string]interface{}
		err := websocket.JSON.Receive(ws, &initialMsg)
		if err != nil {
			fmt.Printf("Failed to read initial WebSocket message: %v\n", err)
			return
		}

		sessionID, ok := initialMsg["sessionId"].(string)
		if !ok {
			fmt.Println("Invalid sessionId in initial message")
			return
		}

		msgType, ok := initialMsg["type"].(string)
		if !ok {
			fmt.Println("Invalid message type in initial message")
			return
		}

		// Get or create session
		_, exists := sm.GetSession(sessionID)
		if !exists {
			sm.CreateSession(sessionID)
		}

		// Register the appropriate connection
		switch msgType {
		case "register_display":
			sm.SetDisplayConnection(sessionID, ws)
			fmt.Printf("Display registered for session %s\n", sessionID)
		case "register_client":
			sm.SetClientConnection(sessionID, ws)
			fmt.Printf("Client registered for session %s\n", sessionID)
		default:
			fmt.Printf("Unknown registration type: %s\n", msgType)
			return
		}

		// Handle subsequent messages
		for {
			var msg map[string]interface{}
			err := websocket.JSON.Receive(ws, &msg)
			if err != nil {
				// Check if it's a normal closure (EOF) or actual error
				if err.Error() == "EOF" {
					fmt.Printf("WebSocket closed normally for session %s\n", sessionID)
				} else {
					fmt.Printf("WebSocket error for session %s: %v\n", sessionID, err)
				}
				break
			}

			sm.handlePairingMessage(sessionID, msg)
		}

		// Cleanup when connection closes
		if session, exists := sm.GetSession(sessionID); exists {
			if session.DisplayConn == ws {
				sm.SetDisplayConnection(sessionID, nil)
				fmt.Printf("Display disconnected for session %s\n", sessionID)
			}
			if session.ClientConn == ws {
				sm.SetClientConnection(sessionID, nil)
				fmt.Printf("Client disconnected for session %s\n", sessionID)

				// Don't invalidate paired sessions when WebSocket closes
				// The client may be redirecting to setup.html and will use the token via HTTP
				if session.State == Paired {
					fmt.Printf("Session %s remains active (client disconnected but still paired)\n", sessionID)
				}
			}
		}
	}
}

// handlePairingMessage processes pairing-related messages
func (sm *SessionManager) handlePairingMessage(sessionID string, msg map[string]interface{}) {
	session, exists := sm.GetSession(sessionID)
	if !exists {
		return
	}

	msgType, ok := msg["type"].(string)
	if !ok {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	switch msgType {
	case "client_key_exchange":
		// Client sends their public key to perform ECDH
		if session.State == WaitingForClient {
			clientPublicKeyStr, ok := msg["clientPublicKey"].(string)
			if !ok {
				fmt.Printf("Invalid client public key in session %s\n", sessionID)
				return
			}

			clientPublicKeyBytes, err := base64.StdEncoding.DecodeString(clientPublicKeyStr)
			if err != nil || len(clientPublicKeyBytes) != 65 {
				fmt.Printf("Failed to decode client public key in session %s: %v (expected 65 bytes, got %d)\n", sessionID, err, len(clientPublicKeyBytes))
				return
			}

			session.ClientPublicKey = clientPublicKeyBytes

			// Compute shared secret
			sharedSecret, err := computeSharedSecret(session.ServerPrivateKey, session.ClientPublicKey)
			if err != nil {
				fmt.Printf("Failed to compute shared secret in session %s: %v\n", sessionID, err)
				return
			}
			session.SharedSecret = sharedSecret

			// Derive cryptographic SAS
			session.CryptoSAS = deriveCryptoSAS(sharedSecret)
			session.State = ReadyForSAS

			// Send SAS to display
			displayMsg := map[string]string{
				"type": "show_sas",
				"sas":  session.CryptoSAS,
			}
			websocket.JSON.Send(session.DisplayConn, displayMsg)

			// Prompt client for SAS
			clientMsg := map[string]string{
				"type": "prompt_for_sas",
			}
			websocket.JSON.Send(session.ClientConn, clientMsg)

			fmt.Printf("Key exchange completed for session %s, SAS: %s\n", sessionID, session.CryptoSAS)
		}

	case "verify_sas":
		// Handle cryptographic SAS verification with rate limiting
		if session.State == ReadyForSAS {
			// Check rate limiting
			now := time.Now()
			if now.Before(session.NextAttemptAfter) {
				// Rate limited - send failure
				failMsg := map[string]string{
					"type":   "pairing_failed",
					"reason": "rate_limited",
				}
				websocket.JSON.Send(session.ClientConn, failMsg)
				fmt.Printf("Rate limited attempt for session %s\n", sessionID)
				return
			}

			providedSAS, ok := msg["sas"].(string)
			if !ok {
				return
			}

			session.AttemptCount++
			session.LastAttempt = now

			if providedSAS == session.CryptoSAS {
				// Success - generate authenticated token
				session.State = Paired

				// Create token with HMAC authentication
				tokenData := fmt.Sprintf("TOKEN_%s_%d", sessionID, time.Now().Unix())
				tokenHMAC := authenticateMessage(session.SharedSecret, []byte(tokenData))
				authenticatedToken := fmt.Sprintf("%s.%s", tokenData, tokenHMAC)

				// Send success to client
				successMsg := map[string]string{
					"type":  "pairing_success",
					"token": authenticatedToken,
				}
				websocket.JSON.Send(session.ClientConn, successMsg)

				// Update display
				displayMsg := map[string]string{
					"type": "pairing_complete",
				}
				websocket.JSON.Send(session.DisplayConn, displayMsg)

				fmt.Printf("Pairing successful for session %s\n", sessionID)

				// Reset expiry timer to 10 minutes for active session
				if session.ExpiryTimer != nil {
					session.ExpiryTimer.Stop()
				}
				session.ExpiryTimer = time.AfterFunc(GetSessionExpiryDuration(), func() {
					sm.CleanupSession(sessionID)
				})
			} else {
				// Failed attempt - implement exponential backoff
				backoffSeconds := 1 << (session.AttemptCount - 1) // 1, 2, 4, 8, 16 seconds
				if backoffSeconds > 16 {
					backoffSeconds = 16
				}
				session.NextAttemptAfter = now.Add(time.Duration(backoffSeconds) * time.Second)

				// Check if max attempts reached
				if session.AttemptCount >= 5 {
					// Invalidate session after max attempts
					session.State = Expired

					failMsg := map[string]string{
						"type":   "pairing_failed",
						"reason": "max_attempts_exceeded",
					}
					websocket.JSON.Send(session.ClientConn, failMsg)

					// Notify display
					displayMsg := map[string]string{
						"type": "session_invalidated",
					}
					websocket.JSON.Send(session.DisplayConn, displayMsg)

					fmt.Printf("Session %s invalidated due to max attempts\n", sessionID)
				} else {
					// Send failure with retry info
					failMsg := map[string]interface{}{
						"type":              "pairing_failed",
						"reason":            "incorrect_sas",
						"attemptsRemaining": 5 - session.AttemptCount,
						"retryAfterSeconds": backoffSeconds,
					}
					websocket.JSON.Send(session.ClientConn, failMsg)

					fmt.Printf("Pairing failed for session %s (wrong SAS), attempt %d/5\n",
						sessionID, session.AttemptCount)
				}
			}
		}

	case "disconnect":
		if session.State == Paired {
			session.State = Expired

			// Send disconnect confirmation to client
			if session.ClientConn != nil {
				confirmMsg := map[string]string{
					"type": "disconnect_confirmed",
				}
				websocket.JSON.Send(session.ClientConn, confirmMsg)
			}

			// Update display
			if session.DisplayConn != nil {
				displayMsg := map[string]string{
					"type": "client_disconnected",
				}
				websocket.JSON.Send(session.DisplayConn, displayMsg)
			}

			fmt.Printf("Session %s manually disconnected\n", sessionID)
		}
	}
}
