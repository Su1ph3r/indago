// Package credentials provides secure credential storage for API keys and tokens.
package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

const (
	defaultStorePath = ".indago/credentials.enc"
	saltSize         = 32
	keySize          = 32 // AES-256
	pbkdf2Iterations = 100000
)

// EncryptedFileStore implements credential storage using an encrypted file.
type EncryptedFileStore struct {
	mu       sync.RWMutex
	path     string
	key      []byte
	salt     []byte
	data     map[string]string
	modified bool
}

// encryptedData represents the stored file format.
type encryptedData struct {
	Salt       string            `json:"salt"`
	IV         string            `json:"iv"`
	Ciphertext string            `json:"ciphertext"`
	Version    int               `json:"version"`
}

// plainData represents the decrypted data structure.
type plainData struct {
	Credentials map[string]string `json:"credentials"`
}

// NewEncryptedFileStore creates a new encrypted file credential store.
func NewEncryptedFileStore(path string) (*EncryptedFileStore, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		path = filepath.Join(home, defaultStorePath)
	}

	store := &EncryptedFileStore{
		path: path,
		data: make(map[string]string),
	}

	// Generate or load encryption key
	if err := store.initializeKey(); err != nil {
		return nil, err
	}

	// Load existing data if present
	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return store, nil
}

// Name returns the store backend name.
func (e *EncryptedFileStore) Name() string {
	return "Encrypted File"
}

// Available always returns true as file storage is always available.
func (e *EncryptedFileStore) Available() bool {
	return true
}

// initializeKey generates or loads the encryption key.
func (e *EncryptedFileStore) initializeKey() error {
	// Try to load existing salt from file
	if data, err := os.ReadFile(e.path); err == nil {
		var encrypted encryptedData
		if err := json.Unmarshal(data, &encrypted); err == nil {
			salt, err := base64.StdEncoding.DecodeString(encrypted.Salt)
			if err == nil && len(salt) == saltSize {
				e.salt = salt
			}
		}
	}

	// Generate new salt if needed
	if e.salt == nil {
		e.salt = make([]byte, saltSize)
		if _, err := rand.Read(e.salt); err != nil {
			return fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	// Derive key from machine-specific identifier + salt
	machineID := getMachineIdentifier()
	e.key = pbkdf2.Key([]byte(machineID), e.salt, pbkdf2Iterations, keySize, sha256.New)

	return nil
}

// getMachineIdentifier returns a machine-specific string for key derivation.
func getMachineIdentifier() string {
	// Combine multiple machine identifiers
	var parts []string

	// Hostname
	if hostname, err := os.Hostname(); err == nil {
		parts = append(parts, hostname)
	}

	// User info
	if home, err := os.UserHomeDir(); err == nil {
		parts = append(parts, home)
	}

	// Machine ID (Linux)
	if data, err := os.ReadFile("/etc/machine-id"); err == nil {
		parts = append(parts, string(data))
	}

	// Hardware UUID (macOS)
	if data, err := os.ReadFile("/var/db/SystemKey"); err == nil {
		parts = append(parts, string(data))
	}

	// Fallback identifier
	if len(parts) == 0 {
		parts = append(parts, "indago-default-key")
	}

	// Hash all parts together
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
	}

	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// load reads and decrypts the credential file.
func (e *EncryptedFileStore) load() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	data, err := os.ReadFile(e.path)
	if err != nil {
		return err
	}

	var encrypted encryptedData
	if err := json.Unmarshal(data, &encrypted); err != nil {
		return fmt.Errorf("failed to parse credential file: %w", err)
	}

	iv, err := base64.StdEncoding.DecodeString(encrypted.IV)
	if err != nil {
		return fmt.Errorf("failed to decode IV: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil {
		return fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Decrypt
	plaintext, err := e.decrypt(ciphertext, iv)
	if err != nil {
		return fmt.Errorf("failed to decrypt credentials: %w", err)
	}

	var plain plainData
	if err := json.Unmarshal(plaintext, &plain); err != nil {
		return fmt.Errorf("failed to parse decrypted data: %w", err)
	}

	e.data = plain.Credentials
	if e.data == nil {
		e.data = make(map[string]string)
	}

	return nil
}

// save encrypts and writes the credential file.
func (e *EncryptedFileStore) save() error {
	// Marshal plaintext data
	plain := plainData{Credentials: e.data}
	plaintext, err := json.Marshal(plain)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Generate IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	// Encrypt
	ciphertext, err := e.encrypt(plaintext, iv)
	if err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	// Create encrypted data structure
	encrypted := encryptedData{
		Salt:       base64.StdEncoding.EncodeToString(e.salt),
		IV:         base64.StdEncoding.EncodeToString(iv),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Version:    1,
	}

	data, err := json.MarshalIndent(encrypted, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted data: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(e.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create credential directory: %w", err)
	}

	// Write file with restricted permissions
	if err := os.WriteFile(e.path, data, 0600); err != nil {
		return fmt.Errorf("failed to write credential file: %w", err)
	}

	e.modified = false
	return nil
}

// encrypt encrypts plaintext using AES-GCM.
func (e *EncryptedFileStore) encrypt(plaintext, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Use iv as nonce (must be 12 bytes for GCM)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Prepend nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts ciphertext using AES-GCM.
func (e *EncryptedFileStore) decrypt(ciphertext, _ []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Set stores a credential in the encrypted file.
func (e *EncryptedFileStore) Set(key, value string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.data[key] = value
	e.modified = true

	return e.save()
}

// Get retrieves a credential from the encrypted file.
func (e *EncryptedFileStore) Get(key string) (string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	value, ok := e.data[key]
	if !ok {
		return "", ErrNotFound
	}

	return value, nil
}

// Delete removes a credential from the encrypted file.
func (e *EncryptedFileStore) Delete(key string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, ok := e.data[key]; !ok {
		return ErrNotFound
	}

	delete(e.data, key)
	e.modified = true

	return e.save()
}

// List returns all credential keys from the encrypted file.
func (e *EncryptedFileStore) List() ([]string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	keys := make([]string, 0, len(e.data))
	for k := range e.data {
		keys = append(keys, k)
	}

	return keys, nil
}

// Path returns the path to the credential file.
func (e *EncryptedFileStore) Path() string {
	return e.path
}
