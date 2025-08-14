package auth

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

type AdminCredentials struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
}

var store = sessions.NewCookieStore([]byte("quando-very-secret-key-that-should-be-random-in-production"))

func init() {
	// Configure session store for CORS compatibility
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false,                // HTTP compatibility
		SameSite: http.SameSiteLaxMode, // Allow cross-site for navigation
	}
}

// HashPassword generates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// GenerateRandomPassword creates a random password with specified length
func GenerateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	password := make([]byte, length)

	for i := range password {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		password[i] = charset[num.Int64()]
	}

	return string(password), nil
}

// CheckPasswordHash compares a password with its hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GetOrCreateAdminCredentials checks for admin config, creates it on first run
func GetOrCreateAdminCredentials() (AdminCredentials, error) {
	configDir, _ := os.UserConfigDir()
	quandoDir := filepath.Join(configDir, "quando")
	configFile := filepath.Join(quandoDir, "config.json")

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		// First time setup - generate random password
		initialPassword, err := GenerateRandomPassword(12)
		if err != nil {
			return AdminCredentials{}, fmt.Errorf("failed to generate random password: %v", err)
		}

		hashedPassword, err := HashPassword(initialPassword)
		if err != nil {
			return AdminCredentials{}, fmt.Errorf("failed to hash password: %v", err)
		}

		creds := AdminCredentials{
			Username:     "admin",
			PasswordHash: hashedPassword,
		}

		// Create directory if it doesn't exist
		os.MkdirAll(quandoDir, 0755)

		file, err := json.MarshalIndent(creds, "", "  ")
		if err != nil {
			return AdminCredentials{}, fmt.Errorf("failed to marshal credentials: %v", err)
		}

		err = os.WriteFile(configFile, file, 0600) // Restrict file permissions
		if err != nil {
			return AdminCredentials{}, fmt.Errorf("failed to write config file: %v", err)
		}

		// IMPORTANT: Inform the user of the initial password
		fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
		fmt.Printf("🔐 FIRST TIME SETUP - ADMIN CREDENTIALS CREATED\n")
		fmt.Printf("   Username: admin\n")
		fmt.Printf("   Password: %s\n", initialPassword)
		fmt.Printf("   ⚠️  IMPORTANT: Save this password! Change it in the admin dashboard.\n")
		fmt.Printf(strings.Repeat("=", 60) + "\n\n")

		return creds, nil
	}

	// Load existing credentials
	file, _ := os.ReadFile(configFile)
	var creds AdminCredentials
	_ = json.Unmarshal(file, &creds)
	return creds, nil
}

// HandleLogin processes login requests
func HandleLogin(creds AdminCredentials) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.ParseForm()
		password := r.FormValue("password")

		if CheckPasswordHash(password, creds.PasswordHash) {
			session, _ := store.Get(r, "quando-session")
			session.Values["authenticated"] = true
			session.Save(r, w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success": true, "message": "Login successful"}`))
		} else {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"success": false, "message": "Invalid credentials"}`, http.StatusUnauthorized)
		}
	}
}

// AuthMiddleware checks if user is authenticated
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "quando-session")

		// Check if user is authenticated
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			// If not an API call, redirect to login page. Otherwise, send an error.
			if r.Header.Get("X-Requested-With") == "XMLHttpRequest" ||
				r.Header.Get("Content-Type") == "application/json" {
				http.Error(w, "Forbidden", http.StatusForbidden)
			} else {
				http.Redirect(w, r, "/login.html", http.StatusFound)
			}
			return
		}
		// If authenticated, call the next handler
		next.ServeHTTP(w, r)
	})
}

// HandleLogout processes logout requests
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "quando-session")
	session.Values["authenticated"] = false
	session.Options.MaxAge = -1 // Delete the session
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"success": true, "message": "Logout successful"}`))
}

// IsAuthenticated checks if the current request is authenticated
func IsAuthenticated(r *http.Request) bool {
	session, _ := store.Get(r, "quando-session")
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		return true
	}
	return false
}

// HandleAuthCheck returns JSON indicating if user is authenticated
func HandleAuthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	result := map[string]bool{
		"authenticated": IsAuthenticated(r),
	}

	json.NewEncoder(w).Encode(result)
}

// UpdateAdminPassword updates the admin password
func UpdateAdminPassword(currentPassword, newPassword string) error {
	configDir, _ := os.UserConfigDir()
	quandoDir := filepath.Join(configDir, "quando")
	configFile := filepath.Join(quandoDir, "config.json")

	// Load existing credentials
	file, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	var creds AdminCredentials
	err = json.Unmarshal(file, &creds)
	if err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}

	// Verify current password
	if !CheckPasswordHash(currentPassword, creds.PasswordHash) {
		return fmt.Errorf("current password is incorrect")
	}

	// Hash new password
	hashedPassword, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %v", err)
	}

	// Update credentials
	creds.PasswordHash = hashedPassword

	// Save updated credentials
	file, err = json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %v", err)
	}

	err = os.WriteFile(configFile, file, 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// HandleChangePassword processes password change requests
func HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	currentPassword := r.FormValue("currentPassword")
	newPassword := r.FormValue("newPassword")

	if currentPassword == "" || newPassword == "" {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"success": false, "message": "Current password and new password are required"}`, http.StatusBadRequest)
		return
	}

	if len(newPassword) < 8 {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"success": false, "message": "New password must be at least 8 characters long"}`, http.StatusBadRequest)
		return
	}

	err := UpdateAdminPassword(currentPassword, newPassword)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(err.Error(), "current password is incorrect") {
			http.Error(w, `{"success": false, "message": "Current password is incorrect"}`, http.StatusUnauthorized)
		} else {
			http.Error(w, fmt.Sprintf(`{"success": false, "message": "Failed to update password: %s"}`, err.Error()), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"success": true, "message": "Password updated successfully"}`))
}
