package server

import (
	"fmt"
	"net"
	"net/http"
	"quando/internal/config"
	"quando/internal/server/auth"
	"quando/internal/server/blocks"
	"quando/internal/server/ip"
	"quando/internal/server/media"
	"quando/internal/server/scripts"
	"quando/internal/server/socket"
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

// CORS middleware to handle cross-origin requests from mobile devices
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow requests from any origin when in remote mode
		if config.Remote() {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			// For local mode, allow localhost and local network
			origin := r.Header.Get("Origin")
			if origin != "" && (strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1") || strings.Contains(origin, "192.168.") || strings.Contains(origin, "10.")) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
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
	http.Redirect(w, req, "/login.html", http.StatusFound)
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

	mux := http.NewServeMux()

	// Public routes (no authentication required)
	mux.HandleFunc("/", indexOrFail)
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

	// Public QR code library for pairing pages
	mux.HandleFunc("/js/qrcode.min.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		http.ServeFile(w, r, "editor/js/qrcode.min.js")
	})

	// Public pairing WebSocket (no authentication required)
	mux.Handle("/ws/handshake", websocket.Handler(HandlePairingWebSocket(sessionManager)))

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

	// WebSocket (protected)
	mux.Handle("/ws/", auth.AuthMiddleware(websocket.Handler(socket.Serve)))

	url := ""
	port = ":80"
	if !config.Remote() {
		// If all hosting is localhost, then bind to local access only; also firewall doesn't need to give permission
		url = "127.0.0.1"
	}
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

	// Apply CORS middleware to all requests
	handler := corsMiddleware(mux)

	err = http.Serve(listen, handler)
	if err != nil && listen != nil {
		fmt.Println("Exiting... ", err)
	}
}
