//go:build darwin
// +build darwin

// Package credentials provides secure credential storage for API keys and tokens.
package credentials

import (
	"os/exec"
	"strings"
)

const (
	keychainService = "indago"
)

// KeychainStore implements credential storage using macOS Keychain.
type KeychainStore struct {
	service string
}

// NewKeychainStore creates a new macOS Keychain credential store.
func NewKeychainStore() *KeychainStore {
	return &KeychainStore{
		service: keychainService,
	}
}

// Name returns the store backend name.
func (k *KeychainStore) Name() string {
	return "macOS Keychain"
}

// Available returns true if Keychain is available.
func (k *KeychainStore) Available() bool {
	_, err := exec.LookPath("security")
	return err == nil
}

// Set stores a credential in the Keychain.
func (k *KeychainStore) Set(key, value string) error {
	// First try to delete existing entry (ignore error if not found)
	_ = k.Delete(key)

	// Add new entry
	cmd := exec.Command("security", "add-generic-password",
		"-s", k.service,
		"-a", key,
		"-w", value,
		"-U", // Update if exists
	)

	if err := cmd.Run(); err != nil {
		return ErrStoreFailed
	}

	return nil
}

// Get retrieves a credential from the Keychain.
func (k *KeychainStore) Get(key string) (string, error) {
	cmd := exec.Command("security", "find-generic-password",
		"-s", k.service,
		"-a", key,
		"-w", // Output password only
	)

	output, err := cmd.Output()
	if err != nil {
		// Check if it's a "not found" error
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 44 { // Item not found
				return "", ErrNotFound
			}
		}
		return "", ErrNotFound
	}

	return strings.TrimSpace(string(output)), nil
}

// Delete removes a credential from the Keychain.
func (k *KeychainStore) Delete(key string) error {
	cmd := exec.Command("security", "delete-generic-password",
		"-s", k.service,
		"-a", key,
	)

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 44 { // Item not found
				return ErrNotFound
			}
		}
		return ErrDeleteFailed
	}

	return nil
}

// List returns all credential keys from the Keychain for this service.
func (k *KeychainStore) List() ([]string, error) {
	// Use security dump-keychain and filter for our service
	cmd := exec.Command("security", "dump-keychain")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var keys []string
	lines := strings.Split(string(output), "\n")

	inOurService := false
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check if this entry is for our service
		if strings.Contains(line, `"svce"<blob>="`) {
			inOurService = strings.Contains(line, `"svce"<blob>="`+k.service+`"`)
		}

		// If we're in our service, look for the account name
		if inOurService && strings.Contains(line, `"acct"<blob>="`) {
			// Extract account name
			start := strings.Index(line, `"acct"<blob>="`) + len(`"acct"<blob>="`)
			end := strings.LastIndex(line, `"`)
			if start > 0 && end > start {
				key := line[start:end]
				keys = append(keys, key)
			}
			inOurService = false
		}
	}

	return keys, nil
}
