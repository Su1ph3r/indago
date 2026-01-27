//go:build !darwin
// +build !darwin

// Package credentials provides secure credential storage for API keys and tokens.
package credentials

// KeychainStore is a stub for non-darwin platforms.
type KeychainStore struct{}

// NewKeychainStore returns nil on non-darwin platforms.
func NewKeychainStore() *KeychainStore {
	return &KeychainStore{}
}

// Name returns the store backend name.
func (k *KeychainStore) Name() string {
	return "macOS Keychain (not available)"
}

// Available returns false on non-darwin platforms.
func (k *KeychainStore) Available() bool {
	return false
}

// Set is not available on non-darwin platforms.
func (k *KeychainStore) Set(key, value string) error {
	return ErrNotSupported
}

// Get is not available on non-darwin platforms.
func (k *KeychainStore) Get(key string) (string, error) {
	return "", ErrNotSupported
}

// Delete is not available on non-darwin platforms.
func (k *KeychainStore) Delete(key string) error {
	return ErrNotSupported
}

// List is not available on non-darwin platforms.
func (k *KeychainStore) List() ([]string, error) {
	return nil, ErrNotSupported
}
