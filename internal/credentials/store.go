// Package credentials provides secure credential storage for API keys and tokens.
package credentials

import (
	"errors"
	"fmt"
	"runtime"
)

// Common errors
var (
	ErrNotFound      = errors.New("credential not found")
	ErrNotSupported  = errors.New("credential storage not supported on this platform")
	ErrAccessDenied  = errors.New("access denied to credential store")
	ErrInvalidKey    = errors.New("invalid credential key")
	ErrStoreFailed   = errors.New("failed to store credential")
	ErrDeleteFailed  = errors.New("failed to delete credential")
)

// Store is the interface for credential storage backends.
type Store interface {
	// Set stores a credential with the given key.
	Set(key, value string) error

	// Get retrieves a credential by key.
	Get(key string) (string, error)

	// Delete removes a credential by key.
	Delete(key string) error

	// List returns all credential keys.
	List() ([]string, error)

	// Name returns the store backend name.
	Name() string

	// Available returns true if this store is available on the current system.
	Available() bool
}

// Credential represents a stored credential with metadata.
type Credential struct {
	Key         string `json:"key"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

// Manager manages credential storage with fallback support.
type Manager struct {
	stores   []Store
	fallback Store
}

// NewManager creates a credential manager with platform-appropriate backends.
func NewManager() (*Manager, error) {
	m := &Manager{
		stores: make([]Store, 0),
	}

	// Add platform-specific stores
	switch runtime.GOOS {
	case "darwin":
		keychain := NewKeychainStore()
		if keychain.Available() {
			m.stores = append(m.stores, keychain)
		}
	case "linux":
		secretService := NewSecretServiceStore()
		if secretService.Available() {
			m.stores = append(m.stores, secretService)
		}
	}

	// Add encrypted file fallback (always available)
	fileStore, err := NewEncryptedFileStore("")
	if err != nil {
		return nil, fmt.Errorf("failed to create file store: %w", err)
	}
	m.fallback = fileStore
	m.stores = append(m.stores, fileStore)

	if len(m.stores) == 0 {
		return nil, ErrNotSupported
	}

	return m, nil
}

// NewManagerWithStore creates a manager with a specific store.
func NewManagerWithStore(store Store) *Manager {
	return &Manager{
		stores:   []Store{store},
		fallback: store,
	}
}

// primaryStore returns the first available store.
func (m *Manager) primaryStore() Store {
	for _, s := range m.stores {
		if s.Available() {
			return s
		}
	}
	return m.fallback
}

// Set stores a credential using the primary store.
func (m *Manager) Set(key, value string) error {
	if key == "" {
		return ErrInvalidKey
	}
	store := m.primaryStore()
	if store == nil {
		return ErrNotSupported
	}
	return store.Set(key, value)
}

// Get retrieves a credential, checking all stores.
func (m *Manager) Get(key string) (string, error) {
	if key == "" {
		return "", ErrInvalidKey
	}

	for _, s := range m.stores {
		if !s.Available() {
			continue
		}
		value, err := s.Get(key)
		if err == nil {
			return value, nil
		}
		if !errors.Is(err, ErrNotFound) {
			// Log but continue to next store
			continue
		}
	}

	return "", ErrNotFound
}

// Delete removes a credential from all stores.
func (m *Manager) Delete(key string) error {
	if key == "" {
		return ErrInvalidKey
	}

	var lastErr error
	deleted := false

	for _, s := range m.stores {
		if !s.Available() {
			continue
		}
		err := s.Delete(key)
		if err == nil {
			deleted = true
		} else if !errors.Is(err, ErrNotFound) {
			lastErr = err
		}
	}

	if deleted {
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return ErrNotFound
}

// List returns all credential keys from all stores.
func (m *Manager) List() ([]string, error) {
	seen := make(map[string]bool)
	var keys []string

	for _, s := range m.stores {
		if !s.Available() {
			continue
		}
		storeKeys, err := s.List()
		if err != nil {
			continue
		}
		for _, k := range storeKeys {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}

	return keys, nil
}

// StoreName returns the name of the primary store being used.
func (m *Manager) StoreName() string {
	store := m.primaryStore()
	if store == nil {
		return "none"
	}
	return store.Name()
}

// Well-known credential keys
const (
	KeyOpenAIAPIKey     = "indago.openai_api_key"
	KeyAnthropicAPIKey  = "indago.anthropic_api_key"
	KeyOllamaURL        = "indago.ollama_url"
	KeyLMStudioURL      = "indago.lmstudio_url"
	KeyDefaultProvider  = "indago.default_provider"
	KeyCallbackURL      = "indago.callback_url"
)

// GetProviderAPIKey retrieves the API key for a given provider.
func (m *Manager) GetProviderAPIKey(provider string) (string, error) {
	switch provider {
	case "openai":
		return m.Get(KeyOpenAIAPIKey)
	case "anthropic":
		return m.Get(KeyAnthropicAPIKey)
	default:
		return "", fmt.Errorf("unknown provider: %s", provider)
	}
}

// SetProviderAPIKey stores the API key for a given provider.
func (m *Manager) SetProviderAPIKey(provider, apiKey string) error {
	switch provider {
	case "openai":
		return m.Set(KeyOpenAIAPIKey, apiKey)
	case "anthropic":
		return m.Set(KeyAnthropicAPIKey, apiKey)
	default:
		return fmt.Errorf("unknown provider: %s", provider)
	}
}
