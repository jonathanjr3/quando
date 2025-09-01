package socket

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/websocket"
)

// tokenValidator is set by the server to map a pairing token to a per-connection MAC key.
// It MUST validate the token and only then return the key. Returning ok=false rejects auth.
var tokenValidator func(token string) (key []byte, ok bool)

// SetSecureTokenValidator allows the HTTP server to inject a validator without import cycles.
func SetSecureTokenValidator(f func(string) ([]byte, bool)) { tokenValidator = f }

type secureSend struct {
	ch     chan string
	encKey []byte // 32 bytes
	macKey []byte // 32 bytes
}

var secureSends []secureSend

func addSecureSend(encKey, macKey []byte) (int, secureSend) {
	newSend := secureSend{ch: make(chan string), encKey: encKey, macKey: macKey}
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
	Type  string `json:"type"`
	Nonce string `json:"nonce"` // base64 IV (16 bytes)
	CT    string `json:"ct"`    // base64 ciphertext
	Tag   string `json:"tag"`   // base64 HMAC over (nonce||ct)
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
			// Encrypt with AES-CTR and authenticate with HMAC (EtM AEAD)
			iv := make([]byte, 16)
			if _, err := io.ReadFull(rand.Reader, iv); err != nil {
				continue
			}
			ct := aesCTREncrypt(send.encKey, iv, []byte(plainJSON))
			tag := mac(send.macKey, append(iv, ct...))
			env := secureEnvelope{Type: "secure", Nonce: base64.StdEncoding.EncodeToString(iv), CT: base64.StdEncoding.EncodeToString(ct), Tag: tag}
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
	// Derive encKey and macKey using HKDF with sessionID as salt
	parts := strings.Split(token, "_")
	if len(parts) < 3 {
		fmt.Println("secure ws: invalid token format for key derivation")
		return
	}
	sessionID := parts[1]
	encKey, macKey := deriveKeys(key, []byte(sessionID))

	// 2) Register secure send channel and start sender
	idx, send := addSecureSend(encKey, macKey)
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
		// Decode envelope
		iv, err1 := base64.StdEncoding.DecodeString(env.Nonce)
		ct, err2 := base64.StdEncoding.DecodeString(env.CT)
		if err1 != nil || err2 != nil || len(iv) != 16 {
			fmt.Println("secure ws: bad envelope fields")
			continue
		}
		// Verify MAC over nonce||ct
		expected := mac(send.macKey, append(iv, ct...))
		if !hmac.Equal([]byte(expected), []byte(env.Tag)) {
			fmt.Println("secure ws: bad tag - dropping message")
			continue
		}
		// Decrypt
		pt, err := aesCTRDecrypt(send.encKey, iv, ct)
		if err != nil {
			fmt.Println("secure ws: decrypt failed")
			continue
		}
		// Forward verified plaintext to secure broadcast bus (will be re-encrypted per-connection)
		BroadcastSecure(string(pt))
	}
}

func deriveKeys(sharedSecret, salt []byte) (encKey []byte, macKey []byte) {
	info := []byte("quando-ws-aead-v1")
	hk := hkdf.New(sha256.New, sharedSecret, salt, info)
	buf := make([]byte, 64)
	if _, err := io.ReadFull(hk, buf); err != nil {
		return nil, nil
	}
	return buf[:32], buf[32:64]
}

func aesCTREncrypt(key, iv, pt []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	ct := make([]byte, len(pt))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ct, pt)
	return ct
}

func aesCTRDecrypt(key, iv, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(pt, ct)
	return pt, nil
}
