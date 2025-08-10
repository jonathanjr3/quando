package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// PairingAwareMiddleware creates middleware that accepts both admin auth and pairing tokens
func PairingAwareMiddleware(sessionManager *SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("DEBUG: PairingAwareMiddleware called for %s\n", r.URL.Path)

			// First check for admin authentication (basic check for now)
			if r.Header.Get("X-Admin-Auth") != "" {
				fmt.Printf("DEBUG: Admin authentication passed\n")
				next.ServeHTTP(w, r)
				return
			}
			token := r.Header.Get("Authorization")
			if token == "" {
				// Also check query parameter for convenience
				token = r.URL.Query().Get("token")
			}

			// If still no token, try to extract from Referer header
			// This handles cases where resources are loaded by pages that have the token
			if token == "" {
				referer := r.Header.Get("Referer")
				if referer != "" {
					fmt.Printf("DEBUG: Checking referer for token: %s\n", referer)
					if strings.Contains(referer, "token=") {
						// Extract token from referer URL
						parts := strings.Split(referer, "token=")
						if len(parts) > 1 {
							tokenPart := parts[1]
							// Handle case where there might be other query parameters after the token
							if ampIndex := strings.Index(tokenPart, "&"); ampIndex != -1 {
								tokenPart = tokenPart[:ampIndex]
							}
							// URL decode the token
							if decodedToken, err := url.QueryUnescape(tokenPart); err == nil {
								token = decodedToken
								fmt.Printf("DEBUG: Extracted token from referer: %s\n", token)
							}
						}
					}
				}
			}

			fmt.Printf("DEBUG: Checking pairing token: %s\n", token)

			if token != "" && sessionManager.ValidateToken(token) {
				fmt.Printf("DEBUG: Pairing token validation passed\n")
				next.ServeHTTP(w, r)
				return
			}

			// Neither authentication method worked
			fmt.Printf("DEBUG: Both auth methods failed\n")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		})
	}
}
