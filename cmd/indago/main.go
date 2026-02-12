// Package main is the entry point for the Indago CLI
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/su1ph3r/indago/internal/analyzer"
	"github.com/su1ph3r/indago/internal/credentials"
	"github.com/su1ph3r/indago/internal/detector"
	"github.com/su1ph3r/indago/internal/fuzzer"
	"github.com/su1ph3r/indago/internal/importer"
	"github.com/su1ph3r/indago/internal/llm"
	"github.com/su1ph3r/indago/internal/parser"
	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/internal/reporter"
	"github.com/su1ph3r/indago/internal/tui"
	"github.com/su1ph3r/indago/pkg/types"
)

var (
	version = "1.3.1"
	cfgFile string
	config  *types.Config
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "indago",
	Short: "Indago - AI-Powered API Security Fuzzer",
	Long: `Indago (Latin: "to track down, investigate") is an AI-powered API security
fuzzer that uses LLMs to understand API business context and generate
intelligent, contextually relevant attack payloads.

Unlike traditional fuzzers that mutate randomly, Indago understands what
parameters mean and generates targeted attacks based on business logic.`,
	Version: version,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan an API for vulnerabilities",
	Long:  `Scan an API using various input formats (OpenAPI, Postman, HAR, Burp, raw URLs)`,
	RunE:  runScan,
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration",
	Long:  `View and modify Indago configuration settings`,
}

var configSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		viper.Set(args[0], args[1])
		return viper.WriteConfig()
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get [key]",
	Short: "Get a configuration value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(viper.Get(args[0]))
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show all configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		for k, v := range viper.AllSettings() {
			fmt.Printf("%s: %v\n", k, v)
		}
		return nil
	},
}

// Credentials commands
var credentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Manage stored credentials",
	Long:  `Store and retrieve API keys and tokens securely using platform keychain or encrypted file storage`,
}

var credentialsSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Store a credential",
	Long: `Store a credential securely. Common keys:
  - openai_api_key     OpenAI API key
  - anthropic_api_key  Anthropic API key
  - ollama_url         Ollama server URL
  - lmstudio_url       LM Studio server URL`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr, err := credentials.NewManager()
		if err != nil {
			return fmt.Errorf("failed to initialize credential store: %w", err)
		}

		key := "indago." + args[0]
		if err := mgr.Set(key, args[1]); err != nil {
			return fmt.Errorf("failed to store credential: %w", err)
		}

		printSuccess("Credential '%s' stored in %s", args[0], mgr.StoreName())
		return nil
	},
}

var credentialsGetCmd = &cobra.Command{
	Use:   "get [key]",
	Short: "Retrieve a credential",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr, err := credentials.NewManager()
		if err != nil {
			return fmt.Errorf("failed to initialize credential store: %w", err)
		}

		key := "indago." + args[0]
		value, err := mgr.Get(key)
		if err != nil {
			return fmt.Errorf("credential not found: %s", args[0])
		}

		fmt.Println(value)
		return nil
	},
}

var credentialsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all stored credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr, err := credentials.NewManager()
		if err != nil {
			return fmt.Errorf("failed to initialize credential store: %w", err)
		}

		keys, err := mgr.List()
		if err != nil {
			return fmt.Errorf("failed to list credentials: %w", err)
		}

		if len(keys) == 0 {
			fmt.Println("No credentials stored")
			return nil
		}

		fmt.Printf("Stored credentials (%s):\n", mgr.StoreName())
		for _, k := range keys {
			// Strip "indago." prefix for display
			displayKey := strings.TrimPrefix(k, "indago.")
			fmt.Printf("  - %s\n", displayKey)
		}
		return nil
	},
}

var credentialsDeleteCmd = &cobra.Command{
	Use:   "delete [key]",
	Short: "Delete a credential",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr, err := credentials.NewManager()
		if err != nil {
			return fmt.Errorf("failed to initialize credential store: %w", err)
		}

		key := "indago." + args[0]
		if err := mgr.Delete(key); err != nil {
			return fmt.Errorf("failed to delete credential: %w", err)
		}

		printSuccess("Credential '%s' deleted", args[0])
		return nil
	},
}

// Interactive command
var interactiveCmd = &cobra.Command{
	Use:   "interactive",
	Short: "Run in interactive TUI mode",
	Long:  `Launch Indago in interactive terminal UI mode with real-time progress, findings list, and triage capabilities`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return tui.RunInteractive()
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.indago.yaml)")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable colored output")

	// Scan command flags
	scanCmd.Flags().StringP("spec", "s", "", "OpenAPI/Swagger specification file")
	scanCmd.Flags().String("postman", "", "Postman collection file")
	scanCmd.Flags().String("har", "", "HAR file")
	scanCmd.Flags().String("burp", "", "Burp Suite XML export file")
	scanCmd.Flags().StringP("url", "u", "", "Base URL for raw endpoints")
	scanCmd.Flags().StringSlice("endpoints", []string{}, "Raw endpoints to scan (comma-separated)")

	scanCmd.Flags().StringP("provider", "p", "", "LLM provider (openai, anthropic, ollama, lmstudio)")
	scanCmd.Flags().String("model", "", "LLM model to use")
	scanCmd.Flags().String("api-key", "", "API key for LLM provider")
	scanCmd.Flags().String("llm-url", "", "Base URL for local LLM (ollama/lmstudio)")

	scanCmd.Flags().StringP("output", "o", "", "Output file path (text format prints to stdout if not specified)")
	scanCmd.Flags().StringP("format", "f", "json", "Output format (json, html, markdown, sarif, text, burp)")
	scanCmd.Flags().Bool("verbose", false, "Verbose output")

	scanCmd.Flags().String("auth-header", "", "Authorization header (e.g., 'Bearer xxx')")
	scanCmd.Flags().StringToString("headers", map[string]string{}, "Additional headers")
	scanCmd.Flags().String("proxy", "", "HTTP proxy URL")

	scanCmd.Flags().Int("concurrency", 10, "Number of concurrent requests")
	scanCmd.Flags().Float64("rate-limit", 10, "Requests per second")
	scanCmd.Flags().Duration("timeout", 30*time.Second, "Request timeout")
	scanCmd.Flags().Bool("no-ssl-verify", false, "Skip SSL certificate verification")

	scanCmd.Flags().StringSlice("attacks", []string{}, "Attack types to enable (empty = all)")
	scanCmd.Flags().StringSlice("skip-attacks", []string{}, "Attack types to skip")
	scanCmd.Flags().Bool("use-llm-payloads", false, "Generate additional context-aware payloads using LLM")
	scanCmd.Flags().Int("llm-concurrency", 8, "Number of concurrent LLM calls for payload generation")
	scanCmd.Flags().String("context", "", "User-provided context about the API (e.g., 'E-commerce API with payment processing and user accounts')")

	// New flags for Phase 1.2
	scanCmd.Flags().Bool("dry-run", false, "Show what would be tested without making requests")
	scanCmd.Flags().String("log-requests", "", "Log all requests/responses to file (JSON format)")
	scanCmd.Flags().Bool("validate-config", false, "Validate configuration and exit")

	// Phase 3 flags
	scanCmd.Flags().Bool("verify", false, "Verify findings with additional testing")
	scanCmd.Flags().String("resume", "", "Resume from checkpoint file")
	scanCmd.Flags().String("checkpoint", "", "Checkpoint file path")
	scanCmd.Flags().Duration("checkpoint-interval", 30*time.Second, "Checkpoint save interval")

	// Phase 4 flags
	scanCmd.Flags().Bool("interactive", false, "Run in interactive TUI mode")

	// Passive checks
	scanCmd.Flags().Bool("passive-checks", false, "Run passive endpoint checks (rate limits, CORS, headers)")

	// Cross-tool integration flags (Phase 4)
	scanCmd.Flags().String("targets-from", "", "Import targets from external tool export (Reticustos/Ariadne JSON)")
	scanCmd.Flags().String("export-waf-blocked", "", "Export WAF-blocked findings to file for BypassBurrito")

	// Add commands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(interactiveCmd)
	rootCmd.AddCommand(credentialsCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configShowCmd)
	credentialsCmd.AddCommand(credentialsSetCmd)
	credentialsCmd.AddCommand(credentialsGetCmd)
	credentialsCmd.AddCommand(credentialsListCmd)
	credentialsCmd.AddCommand(credentialsDeleteCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			viper.AddConfigPath(home)
		}
		viper.AddConfigPath(".")
		viper.SetConfigName(".indago")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("INDAGO")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	if err := viper.ReadInConfig(); err == nil {
		// Config file found
	}

	// Load config
	config = types.DefaultConfig()
	viper.Unmarshal(config)
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupts
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		printWarning("\nInterrupted, shutting down...")
		cancel()
	}()

	// Check for validate-config flag
	validateOnly, _ := cmd.Flags().GetBool("validate-config")
	if validateOnly {
		if err := types.ValidateConfig(config); err != nil {
			printError("Configuration validation failed:")
			fmt.Println(err)
			return err
		}
		printSuccess("Configuration is valid")
		return nil
	}

	// Check for interactive mode
	interactiveMode, _ := cmd.Flags().GetBool("interactive")
	if interactiveMode {
		return tui.RunInteractive()
	}

	// Determine input file
	inputFile, inputType, err := getInputFile(cmd)
	targetsFrom, _ := cmd.Flags().GetString("targets-from")

	// If --targets-from is set, input file is optional
	if err != nil && targetsFrom == "" {
		return err
	}

	// Validate input file exists (only if we have one)
	if inputFile != "" {
		if err := types.ValidateInputFile(inputFile); err != nil {
			return err
		}
	}

	printBanner()

	var endpoints []types.Endpoint

	// Import targets from external tool if specified
	if targetsFrom != "" {
		imp, err := importer.LoadTargets(targetsFrom)
		if err != nil {
			return fmt.Errorf("failed to load targets: %w", err)
		}
		importedEndpoints := importer.ToEndpoints(imp)
		printInfo("Imported %d endpoints from %s", len(importedEndpoints), imp.ExportSource)

		if inputFile != "" {
			printInfo("Input: %s (%s)", inputFile, inputType)
			parsed, err := parseEndpoints(cmd, inputFile)
			if err != nil {
				return fmt.Errorf("failed to parse input: %w", err)
			}
			endpoints = append(parsed, importedEndpoints...)
		} else {
			endpoints = importedEndpoints
		}
	} else {
		printInfo("Input: %s (%s)", inputFile, inputType)
		endpoints, err = parseEndpoints(cmd, inputFile)
		if err != nil {
			return fmt.Errorf("failed to parse input: %w", err)
		}
	}

	printInfo("Parsed %d endpoints", len(endpoints))

	// Setup LLM provider if configured
	var provider llm.Provider
	providerName, _ := cmd.Flags().GetString("provider")
	if providerName == "" {
		providerName = viper.GetString("provider.name")
	}

	if providerName != "" {
		provider, err = setupProvider(cmd, providerName)
		if err != nil {
			printWarning("LLM provider setup failed: %v (continuing without AI analysis)", err)
		} else {
			printInfo("Using LLM provider: %s", provider.Name())

			// Enrich endpoints with AI analysis
			printInfo("Analyzing API with AI...")
			userContext, _ := cmd.Flags().GetString("context")
			if userContext == "" {
				userContext = viper.GetString("user_context")
			}
			if userContext != "" {
				config.UserContext = userContext
				printInfo("Using user-provided context for AI analysis")
			}
			businessAnalyzer := analyzer.NewBusinessAnalyzer(provider, config.UserContext)
			enrichedEndpoints, err := businessAnalyzer.EnrichEndpoints(ctx, endpoints)
			if err != nil {
				printWarning("AI analysis failed: %v (continuing with static analysis)", err)
			} else {
				endpoints = enrichedEndpoints
				printSuccess("AI analysis complete")
			}
		}
	}

	// Configure scan settings from flags
	updateConfigFromFlags(cmd)

	// Generate payloads
	printInfo("Generating payloads...")
	if config.Attacks.UseLLMPayloads && provider != nil {
		printInfo("Dynamic LLM payload generation enabled (concurrency: %d)", config.Attacks.LLMConcurrency)
	}
	payloadGen := payloads.NewGenerator(provider, config.Attacks, config.UserContext)
	var fuzzRequests []payloads.FuzzRequest

	// Use parallel processing for payload generation
	if config.Attacks.LLMConcurrency > 1 && provider != nil {
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, config.Attacks.LLMConcurrency)

		for _, ep := range endpoints {
			wg.Add(1)
			go func(endpoint types.Endpoint) {
				defer wg.Done()
				sem <- struct{}{}        // acquire semaphore
				defer func() { <-sem }() // release semaphore

				reqs := payloadGen.GenerateForEndpoint(ctx, endpoint)

				mu.Lock()
				fuzzRequests = append(fuzzRequests, reqs...)
				mu.Unlock()
			}(ep)
		}
		wg.Wait()
	} else {
		// Sequential processing (no LLM or concurrency disabled)
		for _, ep := range endpoints {
			reqs := payloadGen.GenerateForEndpoint(ctx, ep)
			fuzzRequests = append(fuzzRequests, reqs...)
		}
	}
	printInfo("Generated %d fuzz requests", len(fuzzRequests))

	// Check for dry-run mode
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	if dryRun {
		return runDryRun(fuzzRequests)
	}

	// Setup request logger if enabled
	logFile, _ := cmd.Flags().GetString("log-requests")
	requestLogger, err := fuzzer.NewRequestLogger(logFile)
	if err != nil {
		return fmt.Errorf("failed to create request logger: %w", err)
	}
	defer requestLogger.Close()

	if logFile != "" {
		printInfo("Logging requests to: %s", logFile)
	}

	// Setup fuzzer
	engine := fuzzer.NewEngine(*config)
	responseAnalyzer := detector.NewAnalyzer()

	// Initialize scan stats
	scanStats := types.NewScanStats()

	// Run passive endpoint checks (rate limits, CORS, security headers)
	var passiveFindings []types.Finding
	runPassive, _ := cmd.Flags().GetBool("passive-checks")
	if runPassive {
		printInfo("Running passive endpoint checks...")
		passiveRunner := payloads.NewPassiveCheckRunner()
		passiveRunner.Register(payloads.NewRateLimitChecker())
		passiveRunner.Register(payloads.NewCORSChecker())
		passiveRunner.Register(payloads.NewSecurityHeaderChecker())
		passiveFindings = passiveRunner.RunAll(ctx, endpoints, engine.Client())
		if len(passiveFindings) > 0 {
			printInfo("Passive checks found %d issues", len(passiveFindings))
		}
	}

	// Run fuzzing
	printInfo("Starting scan...")
	startTime := time.Now()

	var findings []types.Finding
	findings = append(findings, passiveFindings...)
	results := engine.Fuzz(ctx, fuzzRequests)

	// Process results
	processedCount := 0
	for result := range results {
		processedCount++

		// Log request if logger is enabled
		if err := requestLogger.Log(result); err != nil {
			printWarning("Failed to log request: %v", err)
		}

		// Update stats
		respSize := int64(0)
		if result.Response != nil {
			respSize = result.Response.ContentLength
		}
		scanStats.Update(result.Duration, result.Error == nil, respSize)

		// Get baseline if needed
		var baseline *types.HTTPResponse
		if result.Error == nil {
			baseline, _ = engine.GetBaseline(ctx, result.Request.Endpoint)
		}

		// Analyze result
		resultFindings := responseAnalyzer.AnalyzeResult(result, baseline)
		findings = append(findings, resultFindings...)

		// Print progress
		if processedCount%100 == 0 {
			printProgress(processedCount, len(fuzzRequests))
		}

		// Print findings as they're discovered
		verbose, _ := cmd.Flags().GetBool("verbose")
		for _, f := range resultFindings {
			printFindingWithVerbose(f, verbose)
		}
	}

	endTime := time.Now()

	// Finalize stats
	scanStats.Finalize(endTime.Sub(startTime))

	// Build scan result
	scanResult := &types.ScanResult{
		ScanID:    uuid.New().String(),
		Target:    getTarget(endpoints),
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  endTime.Sub(startTime),
		Findings:  findings,
		Summary:   types.NewScanSummary(findings),
		Stats:     scanStats,
		Endpoints: len(endpoints),
		Requests:  processedCount,
		Config: &types.ScanConfig{
			Provider:    providerName,
			InputFile:   inputFile,
			InputType:   string(inputType),
			Concurrency: config.Scan.Concurrency,
			RateLimit:   config.Scan.RateLimit,
			Timeout:     int(config.Scan.Timeout.Seconds()),
		},
	}

	// Print summary
	printSummary(scanResult)

	// Export WAF-blocked findings if requested
	wafBlockedFile, _ := cmd.Flags().GetString("export-waf-blocked")
	if wafBlockedFile != "" {
		if err := reporter.ExportWAFBlocked(scanResult, wafBlockedFile); err != nil {
			printWarning("Failed to export WAF-blocked findings: %v", err)
		} else {
			printInfo("WAF-blocked findings exported to: %s", wafBlockedFile)
		}
	}

	// Generate report
	outputFile, _ := cmd.Flags().GetString("output")
	outputFormat, _ := cmd.Flags().GetString("format")
	noColor, _ := cmd.Flags().GetBool("no-color")

	// Handle text format specially - print to stdout if no output file specified
	if (outputFormat == "text" || outputFormat == "txt") && outputFile == "" {
		rep, err := reporter.NewReporterWithColorControl(outputFormat, reporter.DefaultOptions(), noColor)
		if err != nil {
			return fmt.Errorf("failed to create reporter: %w", err)
		}
		fmt.Println() // Add spacing before text report
		if err := rep.Write(scanResult, os.Stdout); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
		return nil
	}

	if outputFile == "" {
		outputFile = fmt.Sprintf("indago-report-%s", time.Now().Format("20060102-150405"))
	}

	rep, err := reporter.NewReporterWithColorControl(outputFormat, reporter.DefaultOptions(), noColor)
	if err != nil {
		return fmt.Errorf("failed to create reporter: %w", err)
	}

	outputPath := outputFile
	if !strings.HasSuffix(outputPath, "."+rep.Extension()) {
		outputPath = outputFile + "." + rep.Extension()
	}

	if err := reporter.WriteToFile(rep, scanResult, outputPath); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	printSuccess("Report saved to: %s", outputPath)

	return nil
}

func getInputFile(cmd *cobra.Command) (string, types.InputType, error) {
	spec, _ := cmd.Flags().GetString("spec")
	postman, _ := cmd.Flags().GetString("postman")
	har, _ := cmd.Flags().GetString("har")
	burp, _ := cmd.Flags().GetString("burp")

	if spec != "" {
		return spec, types.InputTypeOpenAPI, nil
	}
	if postman != "" {
		return postman, types.InputTypePostman, nil
	}
	if har != "" {
		return har, types.InputTypeHAR, nil
	}
	if burp != "" {
		return burp, types.InputTypeBurp, nil
	}

	return "", types.InputTypeUnknown, fmt.Errorf("no input file specified. Use --spec, --postman, --har, or --burp")
}

func parseEndpoints(cmd *cobra.Command, inputFile string) ([]types.Endpoint, error) {
	baseURL, _ := cmd.Flags().GetString("url")

	// Check for raw endpoints
	rawEndpoints, _ := cmd.Flags().GetStringSlice("endpoints")
	if len(rawEndpoints) > 0 {
		rawParser := parser.NewRawParser(baseURL, rawEndpoints)
		return rawParser.Parse()
	}

	// Parse from file
	p, err := parser.NewParser(inputFile, baseURL)
	if err != nil {
		return nil, err
	}

	return p.Parse()
}

func setupProvider(cmd *cobra.Command, name string) (llm.Provider, error) {
	providerConfig := types.ProviderConfig{
		Name: name,
	}

	// Get API key
	apiKey, _ := cmd.Flags().GetString("api-key")
	if apiKey == "" {
		apiKey = viper.GetString("provider.api_key")
	}
	if apiKey == "" {
		// Try environment variables
		switch name {
		case "openai":
			apiKey = os.Getenv("OPENAI_API_KEY")
		case "anthropic":
			apiKey = os.Getenv("ANTHROPIC_API_KEY")
		}
	}
	providerConfig.APIKey = apiKey

	// Get model
	model, _ := cmd.Flags().GetString("model")
	if model == "" {
		model = viper.GetString("provider.model")
	}
	providerConfig.Model = model

	// Get base URL for local providers
	llmURL, _ := cmd.Flags().GetString("llm-url")
	if llmURL == "" {
		llmURL = viper.GetString("provider.base_url")
	}
	providerConfig.BaseURL = llmURL

	// Set defaults
	providerConfig.MaxTokens = 4096
	providerConfig.Temperature = 0.1

	return llm.NewProvider(providerConfig)
}

func updateConfigFromFlags(cmd *cobra.Command) {
	if v, _ := cmd.Flags().GetInt("concurrency"); v > 0 {
		config.Scan.Concurrency = v
	}
	if v, _ := cmd.Flags().GetFloat64("rate-limit"); v > 0 {
		config.Scan.RateLimit = v
	}
	if v, _ := cmd.Flags().GetDuration("timeout"); v > 0 {
		config.Scan.Timeout = v
	}
	if v, _ := cmd.Flags().GetBool("no-ssl-verify"); v {
		config.Scan.VerifySSL = false
	}
	if v, _ := cmd.Flags().GetString("proxy"); v != "" {
		config.HTTP.ProxyURL = v
	}
	if v, _ := cmd.Flags().GetString("auth-header"); v != "" {
		config.HTTP.AuthHeader = v
	}
	if v, _ := cmd.Flags().GetStringToString("headers"); len(v) > 0 {
		for k, val := range v {
			config.HTTP.Headers[k] = val
		}
	}
	if v, _ := cmd.Flags().GetStringSlice("attacks"); len(v) > 0 {
		config.Attacks.Enabled = v
	}
	if v, _ := cmd.Flags().GetStringSlice("skip-attacks"); len(v) > 0 {
		config.Attacks.Disabled = v
	}
	if v, _ := cmd.Flags().GetBool("use-llm-payloads"); v {
		config.Attacks.UseLLMPayloads = true
	}
	if v, _ := cmd.Flags().GetInt("llm-concurrency"); v > 0 {
		config.Attacks.LLMConcurrency = v
	}
}

func getTarget(endpoints []types.Endpoint) string {
	if len(endpoints) == 0 {
		return "unknown"
	}
	return endpoints[0].BaseURL
}

// Printing functions

func printBanner() {
	banner := `
    ____          __
   /  _/___  ____/ /____ _____ ____
   / // __ \/ __  / __ ` + "`" + `/ __ ` + "`" + `/ __ \
 _/ // / / / /_/ / /_/ / /_/ / /_/ /
/___/_/ /_/\__,_/\__,_/\__, /\____/
                      /____/
AI-Powered API Security Fuzzer v%s
`
	fmt.Printf(banner, version)
	fmt.Println()
}

func printInfo(format string, args ...interface{}) {
	color.Cyan("[*] "+format, args...)
}

func printSuccess(format string, args ...interface{}) {
	color.Green("[+] "+format, args...)
}

func printWarning(format string, args ...interface{}) {
	color.Yellow("[!] "+format, args...)
}

func printError(format string, args ...interface{}) {
	color.Red("[-] "+format, args...)
}

func printProgress(current, total int) {
	pct := float64(current) / float64(total) * 100
	fmt.Printf("\r[*] Progress: %d/%d (%.1f%%)", current, total, pct)
}

func printFinding(f types.Finding) {
	printFindingWithVerbose(f, false)
}

func printFindingWithVerbose(f types.Finding, verbose bool) {
	var c *color.Color
	switch f.Severity {
	case types.SeverityCritical:
		c = color.New(color.FgRed, color.Bold)
	case types.SeverityHigh:
		c = color.New(color.FgRed)
	case types.SeverityMedium:
		c = color.New(color.FgYellow)
	case types.SeverityLow:
		c = color.New(color.FgBlue)
	default:
		c = color.New(color.FgCyan)
	}

	c.Printf("\n[%s] %s\n", strings.ToUpper(f.Severity), f.Title)
	fmt.Printf("    Endpoint: %s %s\n", f.Method, f.Endpoint)
	if f.Parameter != "" {
		fmt.Printf("    Parameter: %s\n", f.Parameter)
	}

	// Show request/response in verbose mode
	if verbose && f.Evidence != nil {
		// Show request details
		if f.Evidence.Request != nil {
			color.Cyan("    ─── Request ───")
			fmt.Printf("    %s %s\n", f.Evidence.Request.Method, f.Evidence.Request.URL)
			if len(f.Evidence.Request.Headers) > 0 {
				for k, v := range f.Evidence.Request.Headers {
					fmt.Printf("    %s: %s\n", k, v)
				}
			}
			if f.Evidence.Request.Body != "" {
				body := f.Evidence.Request.Body
				if len(body) > 500 {
					body = body[:500] + "..."
				}
				fmt.Printf("    Body: %s\n", body)
			}
		}

		// Show response details
		if f.Evidence.Response != nil {
			color.Cyan("    ─── Response ───")
			fmt.Printf("    Status: %d %s\n", f.Evidence.Response.StatusCode, f.Evidence.Response.Status)
			if f.Evidence.Response.ResponseTime > 0 {
				fmt.Printf("    Time: %s\n", f.Evidence.Response.ResponseTime)
			}
			if f.Evidence.Response.Body != "" {
				body := f.Evidence.Response.Body
				if len(body) > 500 {
					body = body[:500] + "..."
				}
				fmt.Printf("    Body: %s\n", body)
			}
		}

		// Show matched patterns
		if len(f.Evidence.MatchedData) > 0 {
			color.Yellow("    ─── Matched Patterns ───")
			for _, match := range f.Evidence.MatchedData {
				fmt.Printf("    • %s\n", match)
			}
		}
	}
}

func printSummary(result *types.ScanResult) {
	fmt.Println()
	fmt.Println("=" + strings.Repeat("=", 50))
	fmt.Println("SCAN SUMMARY")
	fmt.Println("=" + strings.Repeat("=", 50))
	fmt.Printf("Target:     %s\n", result.Target)
	fmt.Printf("Duration:   %s\n", result.Duration)
	fmt.Printf("Endpoints:  %d\n", result.Endpoints)
	fmt.Printf("Requests:   %d\n", result.Requests)
	fmt.Println()
	fmt.Printf("Findings:   %d total\n", result.Summary.TotalFindings)

	if result.Summary.CriticalFindings > 0 {
		color.Red("  Critical: %d", result.Summary.CriticalFindings)
	}
	if result.Summary.HighFindings > 0 {
		color.Red("  High:     %d", result.Summary.HighFindings)
	}
	if result.Summary.MediumFindings > 0 {
		color.Yellow("  Medium:   %d", result.Summary.MediumFindings)
	}
	if result.Summary.LowFindings > 0 {
		color.Blue("  Low:      %d", result.Summary.LowFindings)
	}
	if result.Summary.InfoFindings > 0 {
		color.Cyan("  Info:     %d", result.Summary.InfoFindings)
	}

	fmt.Println("=" + strings.Repeat("=", 50))
}

func runDryRun(requests []payloads.FuzzRequest) error {
	simulator := fuzzer.NewDryRunSimulator()
	results := simulator.Simulate(requests)
	summary := simulator.GetSummary(results)

	fmt.Println()
	fmt.Println("=" + strings.Repeat("=", 50))
	fmt.Println("DRY RUN SUMMARY")
	fmt.Println("=" + strings.Repeat("=", 50))
	fmt.Printf("Total Requests:     %d\n", summary.TotalRequests)
	fmt.Printf("Unique Endpoints:   %d\n", summary.UniqueEndpoints)
	fmt.Println()

	// Print by attack type
	fmt.Println("By Attack Type:")
	for attackType, count := range summary.ByAttackType {
		fmt.Printf("  %-20s %d\n", attackType, count)
	}
	fmt.Println()

	// Print by endpoint
	fmt.Println("By Endpoint:")
	grouped := simulator.GroupByEndpoint(results)
	for endpoint, endpointResults := range grouped {
		fmt.Printf("  %s (%d payloads)\n", endpoint, len(endpointResults))

		// Show attack types for this endpoint
		attackCounts := make(map[string]int)
		for _, r := range endpointResults {
			attackCounts[r.PayloadType]++
		}
		for attack, count := range attackCounts {
			fmt.Printf("    - %s: %d\n", attack, count)
		}
	}

	fmt.Println()
	fmt.Println("=" + strings.Repeat("=", 50))
	printSuccess("Dry run complete. No requests were sent.")
	fmt.Println()

	return nil
}

func getConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".config", "indago")
}
