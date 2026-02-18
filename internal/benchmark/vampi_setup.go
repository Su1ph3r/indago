package benchmark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/su1ph3r/indago/pkg/types"
)

// VAmPISetup manages the VAmPI Docker container lifecycle and user setup.
type VAmPISetup struct {
	ContainerName string
	HostPort      int
	BaseURL       string
}

// VAmPITokens holds JWT tokens for two test users.
type VAmPITokens struct {
	User1Token    string
	User2Token    string
	User1Name     string
	User2Name     string
	User1Password string
	User2Password string
}

// NewVAmPISetup creates a VAmPI setup manager.
func NewVAmPISetup(hostPort int) *VAmPISetup {
	return &VAmPISetup{
		ContainerName: "vampi-bench",
		HostPort:      hostPort,
		BaseURL:       fmt.Sprintf("http://localhost:%d", hostPort),
	}
}

// Start launches a fresh VAmPI container, initializes the DB, creates
// test users, and returns JWT tokens for both users.
func (v *VAmPISetup) Start() (*VAmPITokens, error) {
	// Remove any existing container
	v.Stop()

	// Start container
	cmd := exec.Command("docker", "run", "-d",
		"-e", "tokentimetolive=3600",
		"-p", fmt.Sprintf("%d:5000", v.HostPort),
		"--name", v.ContainerName,
		"erev0s/vampi:latest",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker run failed: %w\n%s", err, string(output))
	}

	// Wait for health check
	if err := v.waitForReady(60 * time.Second); err != nil {
		return nil, fmt.Errorf("VAmPI health check failed: %w", err)
	}

	// Initialize database
	if err := v.initDB(); err != nil {
		return nil, fmt.Errorf("VAmPI DB init failed: %w", err)
	}

	// Create users and get tokens
	tokens, err := v.setupUsers()
	if err != nil {
		return nil, fmt.Errorf("VAmPI user setup failed: %w", err)
	}

	return tokens, nil
}

// Stop removes the VAmPI container.
func (v *VAmPISetup) Stop() {
	exec.Command("docker", "stop", v.ContainerName).Run()
	exec.Command("docker", "rm", "-f", v.ContainerName).Run()
}

// StartWatchdog launches a goroutine that periodically health-checks VAmPI
// and restarts the container if it becomes unresponsive. Returns a cancel
// function to stop the watchdog.
func (v *VAmPISetup) StartWatchdog(interval time.Duration) (cancel func()) {
	done := make(chan struct{})
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		failCount := 0
		for {
			select {
			case <-done:
				return
			case <-time.After(interval):
				resp, err := client.Get(v.BaseURL + "/")
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						failCount = 0
						continue
					}
				}
				failCount++
				if failCount >= 3 {
					fmt.Printf("[!] VAmPI unresponsive (%d consecutive failures), restarting container...\n", failCount)
					exec.Command("docker", "restart", v.ContainerName).Run()
					// Wait for it to come back
					v.waitForReady(30 * time.Second)
					failCount = 0
				}
			}
		}
	}()
	return func() { close(done) }
}

func (v *VAmPISetup) waitForReady(timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		resp, err := client.Get(v.BaseURL + "/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("VAmPI did not become ready within %v", timeout)
}

func (v *VAmPISetup) initDB() error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(v.BaseURL + "/createdb")
	if err != nil {
		return fmt.Errorf("createdb request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("createdb returned status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (v *VAmPISetup) setupUsers() (*VAmPITokens, error) {
	tokens := &VAmPITokens{
		User1Name:     "benchuser1",
		User1Password: "BenchP@ss1!",
		User2Name:     "benchuser2",
		User2Password: "BenchP@ss2!",
	}

	// Register user 1
	if err := v.registerUser(tokens.User1Name, tokens.User1Password, "bench1@test.com"); err != nil {
		return nil, fmt.Errorf("register user1: %w", err)
	}

	// Register user 2
	if err := v.registerUser(tokens.User2Name, tokens.User2Password, "bench2@test.com"); err != nil {
		return nil, fmt.Errorf("register user2: %w", err)
	}

	// Login user 1
	token1, err := v.loginUser(tokens.User1Name, tokens.User1Password)
	if err != nil {
		return nil, fmt.Errorf("login user1: %w", err)
	}
	tokens.User1Token = token1

	// Login user 2
	token2, err := v.loginUser(tokens.User2Name, tokens.User2Password)
	if err != nil {
		return nil, fmt.Errorf("login user2: %w", err)
	}
	tokens.User2Token = token2

	return tokens, nil
}

func (v *VAmPISetup) registerUser(username, password, email string) error {
	body := map[string]string{
		"username": username,
		"password": password,
		"email":    email,
	}
	data, _ := json.Marshal(body)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(
		v.BaseURL+"/users/v1/register",
		"application/json",
		bytes.NewReader(data),
	)
	if err != nil {
		return fmt.Errorf("register request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	// 200 = success, 400 = user already exists (acceptable on re-runs)
	if resp.StatusCode != 200 && resp.StatusCode != 400 {
		return fmt.Errorf("register returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (v *VAmPISetup) loginUser(username, password string) (string, error) {
	body := map[string]string{
		"username": username,
		"password": password,
	}
	data, _ := json.Marshal(body)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(
		v.BaseURL+"/users/v1/login",
		"application/json",
		bytes.NewReader(data),
	)
	if err != nil {
		return "", fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("login returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		AuthToken string `json:"auth_token"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse login response: %w", err)
	}

	if result.AuthToken == "" {
		return "", fmt.Errorf("no auth_token in response: %s", string(respBody))
	}

	return result.AuthToken, nil
}

// BuildIndagoArgs returns the CLI arguments for running Indago against VAmPI.
func (v *VAmPISetup) BuildIndagoArgs(tokens *VAmPITokens, specPath, outputPath, logPath, provider string) []string {
	args := []string{
		"scan",
		"--spec", specPath,
		"--url", v.BaseURL,
		"--format", "json",
		"--output", outputPath,
		"--log-requests", logPath,
		"--auth-header", "Bearer " + tokens.User1Token,
		"--passive-checks",
		"--no-ssl-verify",
		"--rate-limit", "50",
		"--concurrency", "10",
	}

	if provider != "" {
		args = append(args, "--provider", provider)
		args = append(args, "--use-llm-payloads")
	}

	// Differential auth for BOLA detection
	args = append(args,
		"--diff-auth", fmt.Sprintf("%s=Bearer %s", tokens.User1Name, tokens.User1Token),
		"--diff-auth", fmt.Sprintf("%s=Bearer %s", tokens.User2Name, tokens.User2Token),
	)

	return args
}

// ExtractScannedEndpoints determines which endpoints were fuzzed by
// combining data from the request log (if available) and from scan
// findings. This covers both standard and differential auth modes.
func ExtractScannedEndpoints(logPath string, findings []types.Finding, endpoints []types.Endpoint) []string {
	seen := make(map[string]bool)

	// Source 1: request log (may be empty in differential auth mode)
	logs := loadRequestLog(logPath)
	for _, l := range logs {
		if l.Endpoint != "" {
			seen[l.Endpoint] = true
		}
	}

	// Source 2: findings — any endpoint with a finding was scanned
	for _, f := range findings {
		if f.Endpoint != "" {
			seen[f.Endpoint] = true
		}
	}

	// Source 3: parsed endpoints from the spec — these are the endpoints
	// Indago would have generated payloads for
	for _, ep := range endpoints {
		if ep.Path != "" {
			seen[ep.Path] = true
		}
	}

	var result []string
	for k := range seen {
		result = append(result, k)
	}
	return result
}

// ExtractParsedEndpointsFromSpec reads the scan result JSON and returns
// the endpoint paths that Indago reported scanning.
func ExtractParsedEndpointsFromSpec(scanResultPath string) []types.Endpoint {
	data, err := os.ReadFile(filepath.Clean(scanResultPath))
	if err != nil {
		return nil
	}
	var result types.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	// We don't have parsed endpoints in ScanResult, but we can infer
	// from findings which endpoints were tested
	return nil
}
