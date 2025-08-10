package server

import (
	"crypto/rand"
	"fmt"
	"math/big"
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

// GenerateSAS creates a 6-digit numeric string
func GenerateSAS() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	return fmt.Sprintf("%06d", n.Int64()+100000)
}

// ValidateToken checks if a pairing token is valid
func (sm *SessionManager) ValidateToken(token string) bool {
	fmt.Printf("DEBUG: Validating token: %s\n", token)

	if !strings.HasPrefix(token, "TOKEN_") {
		fmt.Printf("DEBUG: Token doesn't start with TOKEN_\n")
		return false
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Extract session ID from token (format: TOKEN_{sessionID}_{timestamp})
	parts := strings.Split(token, "_")
	if len(parts) < 3 {
		fmt.Printf("DEBUG: Token doesn't have enough parts: %d\n", len(parts))
		return false
	}

	sessionID := parts[1]
	fmt.Printf("DEBUG: Extracted session ID: %s\n", sessionID)

	session, exists := sm.sessions[sessionID]
	if !exists {
		fmt.Printf("DEBUG: Session %s not found. Available sessions: %v\n", sessionID, func() []string {
			var keys []string
			for k := range sm.sessions {
				keys = append(keys, k)
			}
			return keys
		}())
		return false
	}

	fmt.Printf("DEBUG: Session found, state: %v (Paired=%v)\n", session.State, session.State == Paired)
	// Check if session is in Paired state
	return session.State == Paired
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

	session := &PairingSession{
		ID:        sessionID,
		State:     WaitingForClient,
		CreatedAt: time.Now(),
	}
	sm.sessions[sessionID] = session

	// Set up automatic cleanup after 30 minutes
	session.ExpiryTimer = time.AfterFunc(30*time.Minute, func() {
		sm.CleanupSession(sessionID)
	})

	return session
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*PairingSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	session, exists := sm.sessions[sessionID]
	return session, exists
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
	case "initiate_pairing":
		if session.State == WaitingForClient && session.DisplayConn != nil && session.ClientConn != nil {
			session.State = ReadyForSAS
			session.SAS = GenerateSAS()

			// Send SAS to display
			displayMsg := map[string]string{
				"type": "show_sas",
				"sas":  session.SAS,
			}
			websocket.JSON.Send(session.DisplayConn, displayMsg)

			// Prompt client for SAS
			clientMsg := map[string]string{
				"type": "prompt_for_sas",
			}
			websocket.JSON.Send(session.ClientConn, clientMsg)

			fmt.Printf("Pairing initiated for session %s, SAS: %s\n", sessionID, session.SAS)
		}

	case "verify_sas":
		if session.State == ReadyForSAS {
			providedSAS, ok := msg["sas"].(string)
			if ok && providedSAS == session.SAS {
				session.State = Paired
				token := fmt.Sprintf("TOKEN_%s_%d", sessionID, time.Now().Unix())

				// Send success to client
				successMsg := map[string]string{
					"type":  "pairing_success",
					"token": token,
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
				// Send failure to client
				failMsg := map[string]string{
					"type": "pairing_failed",
				}
				if session.ClientConn != nil {
					websocket.JSON.Send(session.ClientConn, failMsg)
				}
				fmt.Printf("Pairing failed for session %s (wrong SAS)\n", sessionID)
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
