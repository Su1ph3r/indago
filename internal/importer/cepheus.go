package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/su1ph3r/indago/pkg/types"
)

// LoadCepheusFindings reads and parses a Cepheus container posture export
func LoadCepheusFindings(path string) (*types.CepheusImport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read cepheus file: %w", err)
	}

	var imp types.CepheusImport
	if err := json.Unmarshal(data, &imp); err != nil {
		return nil, fmt.Errorf("failed to parse cepheus findings: %w", err)
	}

	if imp.ExportSource != "" && imp.ExportSource != "cepheus" {
		return nil, fmt.Errorf("unsupported export_source '%s', expected 'cepheus'", imp.ExportSource)
	}

	if len(imp.Containers) == 0 && len(imp.EscapePaths) == 0 {
		return nil, fmt.Errorf("no containers or escape paths in cepheus import")
	}

	return &imp, nil
}

// EnrichFindingsWithContainerContext adds container escape risk context to API findings
func EnrichFindingsWithContainerContext(cepheusData *types.CepheusImport, findings []types.Finding) []types.Finding {
	// Build container risk profile
	hasPrivileged := false
	hasHostMount := false
	hasHostNetwork := false
	hasDangerousCaps := false

	for _, container := range cepheusData.Containers {
		if container.Privileged {
			hasPrivileged = true
		}
		for _, mount := range container.Mounts {
			if isHostMount(mount) {
				hasHostMount = true
			}
		}
		if container.HostNetwork {
			hasHostNetwork = true
		}
		for _, cap := range container.Capabilities {
			if isDangerousCapability(cap) {
				hasDangerousCaps = true
			}
		}
	}

	for i := range findings {
		// SSRF + privileged container = container escape risk
		if findings[i].Type == types.AttackSSRF && hasPrivileged {
			findings[i].Tags = appendUnique(findings[i].Tags, "container:escape_risk", "container:privileged")
			findings[i].Description += " [Container Context: Running in privileged container - SSRF could enable container escape]"
		}

		// Path traversal + host mount = host filesystem access
		if findings[i].Type == types.AttackPathTraversal && hasHostMount {
			findings[i].Tags = appendUnique(findings[i].Tags, "container:host_access", "container:host_mount")
			findings[i].Description += " [Container Context: Host filesystem mounted - path traversal could access host files]"
		}

		// Command injection + dangerous capabilities = privilege escalation
		if findings[i].Type == types.AttackCommandInject && (hasDangerousCaps || hasPrivileged) {
			findings[i].Tags = appendUnique(findings[i].Tags, "container:privesc", "container:dangerous_caps")
			findings[i].Description += " [Container Context: Dangerous capabilities present - command injection could lead to privilege escalation]"
		}

		// SSRF + host network = internal network access
		if findings[i].Type == types.AttackSSRF && hasHostNetwork {
			findings[i].Tags = appendUnique(findings[i].Tags, "container:network_escape", "container:host_network")
			findings[i].Description += " [Container Context: Host network mode - SSRF enables access to all host network interfaces]"
		}

		// Add escape path context for any high/critical finding
		if (findings[i].Severity == types.SeverityCritical || findings[i].Severity == types.SeverityHigh) && len(cepheusData.EscapePaths) > 0 {
			findings[i].Tags = appendUnique(findings[i].Tags, "container:escape_paths_available")
		}
	}

	return findings
}

func isHostMount(mount string) bool {
	hostPaths := []string{"/", "/etc", "/var", "/proc", "/sys", "/dev", "/root", "/home"}
	for _, hp := range hostPaths {
		if strings.HasPrefix(mount, hp+":") || mount == hp {
			return true
		}
	}
	return false
}

func isDangerousCapability(cap string) bool {
	dangerous := []string{
		"SYS_ADMIN", "SYS_PTRACE", "SYS_RAWIO", "SYS_MODULE",
		"DAC_READ_SEARCH", "NET_ADMIN", "NET_RAW", "SYS_CHROOT",
	}
	capUpper := strings.ToUpper(cap)
	for _, d := range dangerous {
		if capUpper == d || capUpper == "CAP_"+d {
			return true
		}
	}
	return false
}

// appendUnique appends values to a slice only if they are not already present
func appendUnique(slice []string, values ...string) []string {
	existing := make(map[string]bool, len(slice))
	for _, s := range slice {
		existing[s] = true
	}
	for _, v := range values {
		if !existing[v] {
			slice = append(slice, v)
			existing[v] = true
		}
	}
	return slice
}
