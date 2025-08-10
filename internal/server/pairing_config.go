package server

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type PairingConfig struct {
	QRRefreshIntervalMinutes int `json:"qr_refresh_interval_minutes"`
	SessionExpiryMinutes     int `json:"session_expiry_minutes"`
}

var (
	pairingConfig *PairingConfig
	configMu      sync.RWMutex
)

// getPairingConfigPath returns the platform-specific path for the pairing config file
func getPairingConfigPath() string {
	configDir, _ := os.UserConfigDir()
	quandoDir := filepath.Join(configDir, "quando")
	return filepath.Join(quandoDir, "pairing_config.json")
}

// ensureConfigDir creates the config directory if it doesn't exist
func ensureConfigDir() error {
	configDir, _ := os.UserConfigDir()
	quandoDir := filepath.Join(configDir, "quando")
	return os.MkdirAll(quandoDir, 0755)
} // Default configuration values
var defaultConfig = PairingConfig{
	QRRefreshIntervalMinutes: 5,  // 5 minutes
	SessionExpiryMinutes:     10, // 10 minutes
}

// LoadPairingConfig loads the configuration from file, or creates default if it doesn't exist
func LoadPairingConfig() error {
	configMu.Lock()
	defer configMu.Unlock()

	configFile := getPairingConfigPath()

	// Try to read existing config file
	data, err := os.ReadFile(configFile)
	if err != nil {
		// File doesn't exist, create with defaults
		pairingConfig = &defaultConfig
		return SavePairingConfigUnsafe()
	} // Parse existing config
	pairingConfig = &PairingConfig{}
	if err := json.Unmarshal(data, pairingConfig); err != nil {
		// Invalid config, reset to defaults
		fmt.Printf("Invalid pairing config file, resetting to defaults: %v\n", err)
		pairingConfig = &defaultConfig
		return SavePairingConfigUnsafe()
	}

	// Validate bounds
	if pairingConfig.QRRefreshIntervalMinutes < 1 || pairingConfig.QRRefreshIntervalMinutes > 60 {
		pairingConfig.QRRefreshIntervalMinutes = defaultConfig.QRRefreshIntervalMinutes
	}
	if pairingConfig.SessionExpiryMinutes < 1 || pairingConfig.SessionExpiryMinutes > 240 {
		pairingConfig.SessionExpiryMinutes = defaultConfig.SessionExpiryMinutes
	}

	fmt.Printf("Loaded pairing config: QR refresh=%dm, Session expiry=%dm\n",
		pairingConfig.QRRefreshIntervalMinutes, pairingConfig.SessionExpiryMinutes)
	return nil
}

// SavePairingConfigUnsafe saves the configuration to file (assumes lock is held)
func SavePairingConfigUnsafe() error {
	// Ensure config directory exists
	if err := ensureConfigDir(); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	configFile := getPairingConfigPath()
	data, err := json.MarshalIndent(pairingConfig, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0600)
} // GetPairingConfig returns a copy of the current configuration
func GetPairingConfig() PairingConfig {
	configMu.RLock()
	defer configMu.RUnlock()
	return *pairingConfig
}

// UpdatePairingConfig updates the configuration and saves it to file
func UpdatePairingConfig(newConfig PairingConfig) error {
	configMu.Lock()
	defer configMu.Unlock()

	// Validate bounds
	if newConfig.QRRefreshIntervalMinutes < 1 || newConfig.QRRefreshIntervalMinutes > 60 {
		return fmt.Errorf("QR refresh interval must be between 1 and 60 minutes")
	}
	if newConfig.SessionExpiryMinutes < 1 || newConfig.SessionExpiryMinutes > 240 {
		return fmt.Errorf("session expiry must be between 1 and 240 minutes")
	}

	pairingConfig = &newConfig
	err := SavePairingConfigUnsafe()
	if err == nil {
		fmt.Printf("Updated pairing config: QR refresh=%dm, Session expiry=%dm\n",
			pairingConfig.QRRefreshIntervalMinutes, pairingConfig.SessionExpiryMinutes)
	}
	return err
}

// GetQRRefreshInterval returns the QR refresh interval as a time.Duration
func GetQRRefreshInterval() time.Duration {
	cfg := GetPairingConfig()
	return time.Duration(cfg.QRRefreshIntervalMinutes) * time.Minute
}

// GetSessionExpiryDuration returns the session expiry duration as a time.Duration
func GetSessionExpiryDuration() time.Duration {
	cfg := GetPairingConfig()
	return time.Duration(cfg.SessionExpiryMinutes) * time.Minute
}
