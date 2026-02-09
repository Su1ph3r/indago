package types

// TargetImport represents imported targets from external tools
type TargetImport struct {
	ExportSource  string             `json:"export_source"`
	Format        string             `json:"format"`
	ScanID        string             `json:"scan_id,omitempty"`
	TargetBaseURL string             `json:"target_base_url,omitempty"`
	Endpoints     []ImportedEndpoint `json:"endpoints"`
}

// ImportedEndpoint represents an endpoint from an external tool
type ImportedEndpoint struct {
	Path        string   `json:"path"`
	Method      string   `json:"method"`
	Params      []string `json:"params"`
	Port        int      `json:"port,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	ServiceName string   `json:"service_name,omitempty"`
	BaseURL     string   `json:"base_url,omitempty"`
}

// WAFBlockedExport represents the WAF-blocked findings export
type WAFBlockedExport struct {
	ExportSource string             `json:"export_source"`
	ScanID       string             `json:"scan_id"`
	Target       string             `json:"target"`
	TotalBlocked int                `json:"total_blocked"`
	Targets      []WAFBlockedTarget `json:"targets"`
}

// WAFBlockedTarget represents a single WAF-blocked finding
type WAFBlockedTarget struct {
	OriginalFindingID string `json:"original_finding_id"`
	Endpoint          string `json:"endpoint"`
	Method            string `json:"method"`
	Parameter         string `json:"parameter,omitempty"`
	OriginalPayload   string `json:"original_payload,omitempty"`
	WAFResponseCode   int    `json:"waf_response_code"`
	VulnerabilityType string `json:"vulnerability_type"`
}
