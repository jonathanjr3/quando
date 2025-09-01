package socket

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"golang.org/x/net/websocket"
)

// tokenValidator is set by the server to map a pairing token to a per-connection MAC key.
// It MUST validate the token and only then return the key. Returning ok=false rejects auth.
var tokenValidator func(token string) (key []byte, ok bool)

// SetSecureTokenValidator allows the HTTP server to inject a validator without import cycles.
func SetSecureTokenValidator(f func(string) ([]byte, bool)) { tokenValidator = f }

type secureSend struct {
	ch  chan string
	key []byte // per-connection MAC key
}

var secureSends []secureSend

func addSecureSend(key []byte) (int, secureSend) {
	newSend := secureSend{ch: make(chan string), key: key}
	for i := range secureSends {
		if secureSends[i].ch == nil {
			secureSends[i] = newSend
			return i, newSend
		}
	}
	secureSends = append(secureSends, newSend)
	return len(secureSends) - 1, newSend
}

// secureEnvelope is the wrapped message format.
type secureEnvelope struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	MAC     string `json:"mac"`
}

// mac computes base64(HMAC-SHA256(key, data)).
func mac(key []byte, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// BroadcastSecure wraps and sends a plain JSON payload to all secure connections using their per-connection keys.
func BroadcastSecure(plainJSON string) {
	for _, send := range secureSends {
		if send.ch != nil {
			// Per-connection MAC over the raw JSON string payload
			env := secureEnvelope{Type: "secure", Payload: plainJSON, MAC: mac(send.key, []byte(plainJSON))}
			if b, err := json.Marshal(env); err == nil {
				send.ch <- string(b)
			}
		}
	}
}

func handleSecureSend(ws *websocket.Conn, idx int, send secureSend) {
	for {
		msg, ok := <-send.ch
		if !ok {
			break
		}
		if err := websocket.Message.Send(ws, msg); err != nil {
			secureSends[idx].ch = nil
			break
		}
	}
}

// ServeSecure upgrades a WebSocket and requires an initial auth message: {type:"auth", token:"..."}.
// After auth, all incoming messages must be of type secureEnvelope and will be verified using the derived key.
// Verified application payloads are forwarded to the existing broadcast bus as plain messages for legacy clients.
func ServeSecure(ws *websocket.Conn) {
	defer ws.Close()

	// 1) Expect initial auth
	var init map[string]interface{}
	if err := websocket.JSON.Receive(ws, &init); err != nil {
		fmt.Println("secure ws: failed to read init:", err)
		return
	}
	if init["type"] != "auth" {
		fmt.Println("secure ws: first message not auth")
		return
	}
	token, _ := init["token"].(string)
	if tokenValidator == nil {
		fmt.Println("secure ws: no token validator configured")
		return
	}
	key, ok := tokenValidator(token)
	if !ok || len(key) == 0 {
		fmt.Println("secure ws: token validation failed")
		return
	}

	// 2) Register secure send channel and start sender
	idx, send := addSecureSend(key)
	go handleSecureSend(ws, idx, send)

	// 3) Read loop: require secure envelopes, verify MAC, then forward payload to legacy Broadcast
	for {
		var env secureEnvelope
		if err := websocket.JSON.Receive(ws, &env); err != nil {
			secureSends[idx].ch = nil
			break
		}
		if env.Type != "secure" {
			// Be strict post-auth
			fmt.Println("secure ws: non-secure message rejected")
			continue
		}
		// Verify MAC
		expected := mac(key, []byte(env.Payload))
		if !hmac.Equal([]byte(expected), []byte(env.MAC)) {
			fmt.Println("secure ws: bad mac - dropping message")
			continue
		}

		// Forward verified payload to legacy broadcast bus
		Broadcast(env.Payload)
	}
}
