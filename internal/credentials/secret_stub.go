//go:build !linux
// +build !linux

// Package credentials provides secure credential storage for API keys and tokens.
package credentials

// SecretServiceStore is a stub for non-linux platforms.
type SecretServiceStore struct{}

// NewSecretServiceStore returns nil on non-linux platforms.
func NewSecretServiceStore() *SecretServiceStore {
	return &SecretServiceStore{}
}

// Name returns the store backend name.
func (s *SecretServiceStore) Name() string {
	return "Linux Secret Service (not available)"
}

// Available returns false on non-linux platforms.
func (s *SecretServiceStore) Available() bool {
	return false
}

// Set is not available on non-linux platforms.
func (s *SecretServiceStore) Set(key, value string) error {
	return ErrNotSupported
}

// Get is not available on non-linux platforms.
func (s *SecretServiceStore) Get(key string) (string, error) {
	return "", ErrNotSupported
}

// Delete is not available on non-linux platforms.
func (s *SecretServiceStore) Delete(key string) error {
	return ErrNotSupported
}

// List is not available on non-linux platforms.
func (s *SecretServiceStore) List() ([]string, error) {
	return nil, ErrNotSupported
}
