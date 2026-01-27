//go:build linux
// +build linux

// Package credentials provides secure credential storage for API keys and tokens.
package credentials

import (
	"os/exec"
	"strings"
)

const (
	secretServiceLabel = "indago"
)

// SecretServiceStore implements credential storage using Linux Secret Service (via secret-tool).
type SecretServiceStore struct {
	label string
}

// NewSecretServiceStore creates a new Linux Secret Service credential store.
func NewSecretServiceStore() *SecretServiceStore {
	return &SecretServiceStore{
		label: secretServiceLabel,
	}
}

// Name returns the store backend name.
func (s *SecretServiceStore) Name() string {
	return "Linux Secret Service"
}

// Available returns true if secret-tool is available.
func (s *SecretServiceStore) Available() bool {
	_, err := exec.LookPath("secret-tool")
	return err == nil
}

// Set stores a credential using secret-tool.
func (s *SecretServiceStore) Set(key, value string) error {
	cmd := exec.Command("secret-tool", "store",
		"--label", s.label+" - "+key,
		"application", s.label,
		"key", key,
	)
	cmd.Stdin = strings.NewReader(value)

	if err := cmd.Run(); err != nil {
		return ErrStoreFailed
	}

	return nil
}

// Get retrieves a credential using secret-tool.
func (s *SecretServiceStore) Get(key string) (string, error) {
	cmd := exec.Command("secret-tool", "lookup",
		"application", s.label,
		"key", key,
	)

	output, err := cmd.Output()
	if err != nil {
		return "", ErrNotFound
	}

	value := strings.TrimSpace(string(output))
	if value == "" {
		return "", ErrNotFound
	}

	return value, nil
}

// Delete removes a credential using secret-tool.
func (s *SecretServiceStore) Delete(key string) error {
	cmd := exec.Command("secret-tool", "clear",
		"application", s.label,
		"key", key,
	)

	if err := cmd.Run(); err != nil {
		return ErrDeleteFailed
	}

	return nil
}

// List returns all credential keys from Secret Service.
// Note: secret-tool doesn't have a built-in list command, so this is limited.
func (s *SecretServiceStore) List() ([]string, error) {
	// secret-tool search returns attributes for matching items
	cmd := exec.Command("secret-tool", "search",
		"application", s.label,
	)

	output, err := cmd.Output()
	if err != nil {
		// No items found is not an error
		return []string{}, nil
	}

	var keys []string
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "attribute.key = ") {
			key := strings.TrimPrefix(line, "attribute.key = ")
			keys = append(keys, key)
		}
	}

	return keys, nil
}
