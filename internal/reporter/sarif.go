package reporter

import (
	"encoding/json"
	"io"

	"github.com/su1ph3r/indago/pkg/types"
)

// SARIFReporter generates SARIF reports for CI/CD integration
type SARIFReporter struct {
	options ReportOptions
}

// NewSARIFReporter creates a new SARIF reporter
func NewSARIFReporter(options ReportOptions) *SARIFReporter {
	return &SARIFReporter{options: options}
}

// Format returns the format name
func (r *SARIFReporter) Format() string {
	return "sarif"
}

// Extension returns the file extension
func (r *SARIFReporter) Extension() string {
	return "sarif"
}

// Generate generates a SARIF report
func (r *SARIFReporter) Generate(result *types.ScanResult) ([]byte, error) {
	sarif := r.buildSARIF(result)
	return json.MarshalIndent(sarif, "", "  ")
}

// Write writes the SARIF report to a writer
func (r *SARIFReporter) Write(result *types.ScanResult, w io.Writer) error {
	data, err := r.Generate(result)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// buildSARIF builds the SARIF structure
func (r *SARIFReporter) buildSARIF(result *types.ScanResult) *SARIFLog {
	// Sort findings by severity (critical first)
	SortFindingsBySeverity(result.Findings)
	sarif := &SARIFLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:            "Indago",
						Version:         "1.0.0",
						InformationURI:  "https://github.com/su1ph3r/indago",
						SemanticVersion: "1.0.0",
						Rules:           r.buildRules(result.Findings),
					},
				},
				Results: r.buildResults(result.Findings),
				Invocations: []SARIFInvocation{
					{
						ExecutionSuccessful: true,
						StartTimeUTC:        result.StartTime.Format("2006-01-02T15:04:05Z"),
						EndTimeUTC:          result.EndTime.Format("2006-01-02T15:04:05Z"),
					},
				},
			},
		},
	}

	return sarif
}

// buildRules builds SARIF rules from findings
func (r *SARIFReporter) buildRules(findings []types.Finding) []SARIFRule {
	ruleMap := make(map[string]SARIFRule)

	for _, f := range findings {
		ruleID := f.Type
		if _, exists := ruleMap[ruleID]; exists {
			continue
		}

		rule := SARIFRule{
			ID:   ruleID,
			Name: f.Title,
			ShortDescription: SARIFMessage{
				Text: f.Title,
			},
			FullDescription: SARIFMessage{
				Text: f.Description,
			},
			DefaultConfiguration: SARIFConfiguration{
				Level: severityToSARIFLevel(f.Severity),
			},
			Help: SARIFMessage{
				Text: f.Remediation,
			},
			Properties: SARIFRuleProperties{
				Tags: []string{f.Type, f.Confidence},
			},
		}

		if f.CWE != "" {
			rule.Properties.Tags = append(rule.Properties.Tags, f.CWE)
		}

		ruleMap[ruleID] = rule
	}

	rules := make([]SARIFRule, 0, len(ruleMap))
	for _, rule := range ruleMap {
		rules = append(rules, rule)
	}

	return rules
}

// buildResults builds SARIF results from findings
func (r *SARIFReporter) buildResults(findings []types.Finding) []SARIFResult {
	results := make([]SARIFResult, 0, len(findings))

	for _, f := range findings {
		result := SARIFResult{
			RuleID:  f.Type,
			Level:   severityToSARIFLevel(f.Severity),
			Message: SARIFMessage{Text: f.Description},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: f.Method + " " + f.Endpoint,
						},
					},
					LogicalLocations: []SARIFLogicalLocation{
						{
							Name:               f.Endpoint,
							FullyQualifiedName: f.Method + " " + f.Endpoint,
							Kind:               "endpoint",
						},
					},
				},
			},
			Fingerprints: map[string]string{
				"indago/v1": f.ID,
			},
			Properties: SARIFResultProperties{
				Confidence:  f.Confidence,
				Parameter:   f.Parameter,
				Payload:     f.Payload,
				CWE:         f.CWE,
				Remediation: f.Remediation,
				CurlCommand: GenerateCurlFromFinding(&f),
			},
		}

		results = append(results, result)
	}

	return results
}

// severityToSARIFLevel converts severity to SARIF level
func severityToSARIFLevel(severity string) string {
	switch severity {
	case types.SeverityCritical, types.SeverityHigh:
		return "error"
	case types.SeverityMedium:
		return "warning"
	case types.SeverityLow, types.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// SARIF data structures

// SARIFLog is the root SARIF structure
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single scan run
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

// SARIFTool represents the scanning tool
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the tool driver
type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Rules           []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule represents a detection rule
type SARIFRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name,omitempty"`
	ShortDescription     SARIFMessage        `json:"shortDescription,omitempty"`
	FullDescription      SARIFMessage        `json:"fullDescription,omitempty"`
	DefaultConfiguration SARIFConfiguration  `json:"defaultConfiguration,omitempty"`
	Help                 SARIFMessage        `json:"help,omitempty"`
	Properties           SARIFRuleProperties `json:"properties,omitempty"`
}

// SARIFConfiguration represents rule configuration
type SARIFConfiguration struct {
	Level string `json:"level"`
}

// SARIFRuleProperties represents rule properties
type SARIFRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

// SARIFResult represents a finding
type SARIFResult struct {
	RuleID       string                `json:"ruleId"`
	Level        string                `json:"level"`
	Message      SARIFMessage          `json:"message"`
	Locations    []SARIFLocation       `json:"locations,omitempty"`
	Fingerprints map[string]string     `json:"fingerprints,omitempty"`
	Properties   SARIFResultProperties `json:"properties,omitempty"`
}

// SARIFResultProperties represents result properties
type SARIFResultProperties struct {
	Confidence  string `json:"confidence,omitempty"`
	Parameter   string `json:"parameter,omitempty"`
	Payload     string `json:"payload,omitempty"`
	CWE         string `json:"cwe,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	CurlCommand string `json:"curlCommand,omitempty"`
}

// SARIFMessage represents a message
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a location
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation  `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

// SARIFPhysicalLocation represents a physical location
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

// SARIFArtifactLocation represents an artifact location
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFLogicalLocation represents a logical location
type SARIFLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// SARIFInvocation represents an invocation
type SARIFInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUTC        string `json:"startTimeUtc,omitempty"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}
