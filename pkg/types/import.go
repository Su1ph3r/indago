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

// BurritoBypassImport represents imported WAF bypass results from BypassBurrito
type BurritoBypassImport struct {
	ExportSource string           `json:"export_source"`
	ScanID       string           `json:"scan_id,omitempty"`
	Target       string           `json:"target,omitempty"`
	Bypasses     []BurritoBypass  `json:"bypasses"`
}

// BurritoBypass represents a single successful WAF bypass from BypassBurrito
type BurritoBypass struct {
	OriginalFindingID string            `json:"original_finding_id,omitempty"`
	Endpoint          string            `json:"endpoint"`
	Method            string            `json:"method"`
	Parameter         string            `json:"parameter,omitempty"`
	BypassPayload     string            `json:"bypass_payload"`
	BypassTechnique   string            `json:"bypass_technique,omitempty"`
	VulnerabilityType string            `json:"vulnerability_type"`
	StatusCode        int               `json:"status_code,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
}

// VinculumExport represents findings exported for Vinculum correlation
type VinculumExport struct {
	ToolSource string            `json:"tool_source"`
	ScanID     string            `json:"scan_id"`
	Target     string            `json:"target"`
	Timestamp  string            `json:"timestamp"`
	Findings   []VinculumFinding `json:"findings"`
}

// VinculumFinding represents a single finding in Vinculum format
type VinculumFinding struct {
	ID                string `json:"id"`
	Type              string `json:"type"`
	Severity          string `json:"severity"`
	Confidence        string `json:"confidence"`
	Title             string `json:"title"`
	Description       string `json:"description"`
	Endpoint          string `json:"endpoint"`
	Method            string `json:"method"`
	Parameter         string `json:"parameter,omitempty"`
	CWE               string `json:"cwe,omitempty"`
	RawRequest        string `json:"raw_request,omitempty"`
	RawResponse       string `json:"raw_response,omitempty"`
}

// AriadneExport represents findings exported with attack path context for Ariadne
type AriadneExport struct {
	ToolSource  string              `json:"tool_source"`
	ScanID      string              `json:"scan_id"`
	Target      string              `json:"target"`
	Timestamp   string              `json:"timestamp"`
	AttackPaths []AriadneAttackPath `json:"attack_paths"`
}

// AriadneAttackPath represents a group of findings forming an attack path
type AriadneAttackPath struct {
	Endpoint     string           `json:"endpoint"`
	Method       string           `json:"method"`
	Severity     string           `json:"severity"`
	Findings     []AriadneFinding `json:"findings"`
	Prerequisites []string        `json:"prerequisites,omitempty"`
	Successors    []string        `json:"successors,omitempty"`
}

// AriadneFinding represents a single finding within an attack path
type AriadneFinding struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Parameter   string `json:"parameter,omitempty"`
	Payload     string `json:"payload,omitempty"`
	CWE         string `json:"cwe,omitempty"`
}

// CepheusImport represents imported container posture data from Cepheus
type CepheusImport struct {
	ExportSource string              `json:"export_source"`
	ScanID       string              `json:"scan_id,omitempty"`
	ClusterName  string              `json:"cluster_name,omitempty"`
	Containers   []CepheusContainer  `json:"containers"`
	EscapePaths  []CepheusEscapePath `json:"escape_paths,omitempty"`
}

// CepheusContainer represents a container's security posture
type CepheusContainer struct {
	Name         string   `json:"name"`
	Image        string   `json:"image"`
	Namespace    string   `json:"namespace,omitempty"`
	Privileged   bool     `json:"privileged"`
	Capabilities []string `json:"capabilities,omitempty"`
	Mounts       []string `json:"mounts,omitempty"`
	RunAsRoot    bool     `json:"run_as_root"`
	HostNetwork  bool     `json:"host_network"`
	HostPID      bool     `json:"host_pid"`
}

// CepheusEscapePath represents a discovered container escape technique
type CepheusEscapePath struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Container   string `json:"container"`
	Technique   string `json:"technique"`
	Prereqs     string `json:"prerequisites,omitempty"`
}

// NubicustosImport represents imported cloud security findings from Nubicustos
type NubicustosImport struct {
	ExportSource   string                    `json:"export_source"`
	ScanID         string                    `json:"scan_id,omitempty"`
	CloudProvider  string                    `json:"cloud_provider,omitempty"` // aws, gcp, azure
	AccountID      string                    `json:"account_id,omitempty"`
	Findings       []NubicustosCloudFinding  `json:"findings"`
	Infrastructure *NubicustosInfrastructure `json:"infrastructure,omitempty"`
}

// NubicustosCloudFinding represents a single cloud security finding
type NubicustosCloudFinding struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`     // s3_public, iam_overprivileged, security_group_open, etc.
	Severity    string   `json:"severity"`
	Resource    string   `json:"resource"` // ARN or resource identifier
	Region      string   `json:"region,omitempty"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// NubicustosInfrastructure represents discovered infrastructure
type NubicustosInfrastructure struct {
	Endpoints     []string `json:"endpoints,omitempty"`     // API endpoints found
	S3Buckets     []string `json:"s3_buckets,omitempty"`
	LoadBalancers []string `json:"load_balancers,omitempty"`
}
