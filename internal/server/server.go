package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"quando/internal/config"
	"quando/internal/server/auth"
	"quando/internal/server/blocks"
	"quando/internal/server/ip"
	"quando/internal/server/media"
	"quando/internal/server/scripts"
	"quando/internal/server/socket"
	"strconv"
	"strings"

	"golang.org/x/net/websocket"
)

var listen net.Listener
var port string

type Handler struct {
	Url  string
	Func func(w http.ResponseWriter, req *http.Request)
}

func Port() string {
	return port
}

// isAllowedLocalOrigin validates if an origin is from a trusted local source
func isAllowedLocalOrigin(originStr string) bool {
	if originStr == "" {
		return false
	}

	// Parse the origin URL
	originURL, err := url.Parse(originStr)
	if err != nil {
		return false
	}

	// Extract hostname (removes port if present)
	hostname := originURL.Hostname()
	if hostname == "" {
		return false
	}

	// Check for exact localhost matches
	if hostname == "localhost" || hostname == "127.0.0.1" {
		return true
	}

	// Check for private network ranges (RFC 1918)
	// 192.168.0.0/16
	if strings.HasPrefix(hostname, "192.168.") {
		parts := strings.Split(hostname, ".")
		if len(parts) == 4 {
			// Validate it's actually an IP (all parts are numeric)
			for _, part := range parts {
				if len(part) == 0 || len(part) > 3 {
					return false
				}
				for _, char := range part {
					if char < '0' || char > '9' {
						return false
					}
				}
			}
			return true
		}
	}

	// Check for 10.0.0.0/8 private range
	if strings.HasPrefix(hostname, "10.") {
		parts := strings.Split(hostname, ".")
		if len(parts) == 4 {
			// Validate it's actually an IP
			for _, part := range parts {
				if len(part) == 0 || len(part) > 3 {
					return false
				}
				for _, char := range part {
					if char < '0' || char > '9' {
						return false
					}
				}
			}
			return true
		}
	}

	// Check for 172.16.0.0/12 private range
	if strings.HasPrefix(hostname, "172.") {
		parts := strings.Split(hostname, ".")
		if len(parts) == 4 && len(parts[1]) > 0 {
			// Validate second octet is between 16-31 for 172.16.0.0/12
			if secondOctet, err := strconv.Atoi(parts[1]); err == nil && secondOctet >= 16 && secondOctet <= 31 {
				// Validate all parts are numeric
				for _, part := range parts {
					if len(part) == 0 || len(part) > 3 {
						return false
					}
					for _, char := range part {
						if char < '0' || char > '9' {
							return false
						}
					}
				}
				return true
			}
		}
	}

	return false
}

// CORS middleware to handle cross-origin requests from mobile devices
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Always allow localhost and 127.0.0.1 regardless of mode
		// Use flexible pattern matching for any port
		if origin != "" {
			originURL, err := url.Parse(origin)
			if err == nil {
				hostname := originURL.Hostname()
				if hostname == "localhost" || hostname == "127.0.0.1" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				} else if config.Remote() {
					// In remote mode, allow any origin for cross-device access
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else {
					// For local mode, use secure origin validation
					if isAllowedLocalOrigin(origin) {
						w.Header().Set("Access-Control-Allow-Origin", origin)
					}
				}
			}
		} else if config.Remote() {
			// Fallback for remote mode when no origin header
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func indexOrFail(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}

	// Check if user is authenticated
	if auth.IsAuthenticated(req) {
		// Redirect authenticated users to admin dashboard
		http.Redirect(w, req, "/admin", http.StatusFound)
		return
	}

	// Redirect unauthenticated users to login
	http.Redirect(w, req, "/login", http.StatusFound)
}

func favicon(w http.ResponseWriter, req *http.Request) {
	http.ServeFile(w, req, "./editor/favicon.ico")
}

func showStartup(host string) {
	fmt.Println("..serving HTTP on : ", host)
}

// Overrides windows local machine map, which can default to text/plain for javascript files
// See https://stackoverflow.com/questions/54835510/getting-mime-type-text-plain-error-in-golang-while-serving-css
func fileServe(w http.ResponseWriter, req *http.Request) {
	if strings.HasSuffix(req.RequestURI, ".js") {
		w.Header().Set("Content-Type", "text/javascript")
	}
	req.RequestURI = "." + req.RequestURI
	http.FileServer(http.Dir("")).ServeHTTP(w, req)
}

func Quit() {
	fmt.Println("Exiting...")
	tmp := listen
	listen = nil
	tmp.Close()
}

func ServeHTTPandIO(handlers []Handler) {
	var err error

	// Initialize admin credentials
	creds, err := auth.GetOrCreateAdminCredentials()
	if err != nil {
		fmt.Println("Failed to initialize admin credentials:", err)
		return
	}

	// Initialize pairing session manager
	sessionManager := NewSessionManager()

	// Initialize pairing configuration
	if err := LoadPairingConfig(); err != nil {
		fmt.Printf("Warning: Failed to load pairing config: %v\n", err)
	}

	mux := http.NewServeMux()

	// Public routes (no authentication required)
	mux.HandleFunc("/", indexOrFail)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "editor/login.html")
	})
	mux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "editor/login.html")
	})
	mux.HandleFunc("/api/login", auth.HandleLogin(creds))
	mux.HandleFunc("/api/logout", auth.HandleLogout)
	mux.HandleFunc("/favicon.ico", favicon)
	mux.HandleFunc("/ip", ip.HandlePrivateIP)

	// Public pairing routes (no authentication required)
	mux.HandleFunc("/join", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "editor/join.html")
	})
	mux.HandleFunc("/pair/", func(w http.ResponseWriter, r *http.Request) {
		// Extract session ID from URL path
		path := r.URL.Path
		if len(path) > 6 { // "/pair/" is 6 characters
			http.ServeFile(w, r, "editor/pair.html")
		} else {
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("/goodbye", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "editor/goodbye.html")
	})

	// Public QR code library for pairing pages
	mux.HandleFunc("/js/qrcode.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		http.ServeFile(w, r, "editor/js/qrcode.min.js")
	})

	// Public crypto libraries for pairing pages (no authentication required)
	mux.HandleFunc("/client/extlib/elliptic.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		http.ServeFile(w, r, "client/extlib/elliptic.min.js")
	})
	mux.HandleFunc("/client/extlib/crypto-js.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		http.ServeFile(w, r, "client/extlib/crypto-js.min.js")
	})

	// Public pairing WebSocket (no authentication required)
	mux.Handle("/ws/handshake", websocket.Handler(HandlePairingWebSocket(sessionManager)))

	// Secure post-pair WebSocket: token-authenticated, HMAC-protected
	socket.SetSecureTokenValidator(func(token string) ([]byte, bool) {
		// Token format expected by current code: TOKEN_{sessionID}_{ts}.<base64 HMAC>
		// Validate via existing session manager and, if valid, return the session's shared secret as MAC key
		if !sessionManager.ValidateToken(token) { // will also check session state
			return nil, false
		}
		// Extract sessionID to retrieve the key
		parts := strings.Split(token, "_")
		if len(parts) < 3 {
			return nil, false
		}
		sessionID := parts[1]
		if sess, ok := sessionManager.GetSession(sessionID); ok && sess != nil && len(sess.SharedSecret) > 0 {
			return sess.SharedSecret, true
		}
		return nil, false
	})
	mux.Handle("/ws/secure", websocket.Handler(socket.ServeSecure))

	// Public session info endpoint for QR code generation
	mux.HandleFunc("/api/session/", func(w http.ResponseWriter, r *http.Request) {
		// Extract session ID from URL path
		path := strings.TrimPrefix(r.URL.Path, "/api/session/")
		sessionId := strings.TrimSuffix(path, "/info")
		if sessionId == "" {
			http.Error(w, "Session ID required", http.StatusBadRequest)
			return
		}

		sessionInfo, exists := sessionManager.GetSessionInfo(sessionId)
		if !exists {
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}

		// Marshal session info to JSON
		jsonData, err := json.Marshal(sessionInfo)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonData)
	})

	// Disconnect endpoint for paired clients
	mux.HandleFunc("/disconnect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.FormValue("token")
		}

		if token != "" && sessionManager.InvalidateTokenSession(token) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"success": true, "message": "Session disconnected"}`))
		} else {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
		}
	})

	// Protected admin API routes
	mux.HandleFunc("/api/change-password", func(w http.ResponseWriter, r *http.Request) {
		auth.AuthMiddleware(http.HandlerFunc(auth.HandleChangePassword)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/pairing-config", func(w http.ResponseWriter, r *http.Request) {
		auth.AuthMiddleware(http.HandlerFunc(HandleGetPairingConfig)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/update-pairing-config", func(w http.ResponseWriter, r *http.Request) {
		auth.AuthMiddleware(http.HandlerFunc(HandleUpdatePairingConfig)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/api/auth-check", auth.HandleAuthCheck)

	// Protected admin routes
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		auth.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "editor/admin.html")
		})).ServeHTTP(w, r)
	})

	// Protected API routes
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/blocks", blocks.Handle)
	protectedMux.HandleFunc("/media/", media.HandleMedia)
	protectedMux.HandleFunc("/images/", media.HandleGetMediaDirectory)
	protectedMux.HandleFunc("/audio/", media.HandleGetMediaDirectory)
	protectedMux.HandleFunc("/video/", media.HandleGetMediaDirectory)
	protectedMux.HandleFunc("/objects/", media.HandleGetMediaDirectory)

	// Add additional handlers to protected routes
	for _, handler := range handlers {
		protectedMux.HandleFunc(handler.Url, handler.Func)
	}

	// Apply pairing-aware middleware to script routes
	mux.Handle("/scripts", PairingAwareMiddleware(sessionManager)(http.HandlerFunc(scripts.HandleDirectory)))
	mux.Handle("/scripts/", PairingAwareMiddleware(sessionManager)(http.HandlerFunc(scripts.HandleFile)))

	// Apply authentication middleware to other protected routes
	mux.Handle("/blocks", auth.AuthMiddleware(protectedMux))
	mux.Handle("/media/", auth.AuthMiddleware(protectedMux))
	mux.Handle("/images/", auth.AuthMiddleware(protectedMux))
	mux.Handle("/audio/", auth.AuthMiddleware(protectedMux))
	mux.Handle("/video/", auth.AuthMiddleware(protectedMux))
	mux.Handle("/objects/", auth.AuthMiddleware(protectedMux))

	// Protected file serving
	mux.Handle("/editor/", auth.AuthMiddleware(http.HandlerFunc(fileServe)))
	mux.Handle("/client/", PairingAwareMiddleware(sessionManager)(http.HandlerFunc(fileServe)))
	mux.Handle("/common/", PairingAwareMiddleware(sessionManager)(http.HandlerFunc(fileServe)))
	mux.Handle("/dashboard/", auth.AuthMiddleware(http.HandlerFunc(fileServe)))

	// Legacy WebSocket removed: all realtime messaging must use /ws/secure with pairing token

	url := ""
	port = ":80"

	if !config.Remote() {
		// If all hosting is localhost, then bind to local access only; also firewall doesn't need to give permission
		url = "127.0.0.1"
	}

	// Apply CORS middleware to all requests
	handler := corsMiddleware(mux)

	// Start HTTP server
	listen, err = net.Listen("tcp", url+port)
	if err != nil {
		port = ":8080"
		listen, err = net.Listen("tcp", url+port)
		if err != nil {
			fmt.Println("Failed to start server - port 80 and 8080 may already be in use - exiting...\n", err)
			return
		}
	}
	showStartup(url + port)

	err = http.Serve(listen, handler)
	if err != nil && listen != nil {
		fmt.Println("Exiting... ", err)
	}
}
