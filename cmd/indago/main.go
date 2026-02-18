// Package main is the entry point for the Indago CLI
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
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
	"github.com/su1ph3r/indago/internal/callback"
	"github.com/su1ph3r/indago/internal/chains"
	"github.com/su1ph3r/indago/internal/checkpoint"
	"github.com/su1ph3r/indago/internal/credentials"
	"github.com/su1ph3r/indago/internal/detector"
	"github.com/su1ph3r/indago/internal/fuzzer"
	"github.com/su1ph3r/indago/internal/importer"
	"github.com/su1ph3r/indago/internal/inference"
	"github.com/su1ph3r/indago/internal/llm"
	"github.com/su1ph3r/indago/internal/parser"
	"github.com/su1ph3r/indago/internal/payloads"
	"github.com/su1ph3r/indago/internal/plugin"
	"github.com/su1ph3r/indago/internal/reporter"
	"github.com/su1ph3r/indago/internal/rules"
	"github.com/su1ph3r/indago/internal/tui"
	"github.com/su1ph3r/indago/internal/verify"
	"github.com/su1ph3r/indago/internal/waf"
	"github.com/su1ph3r/indago/pkg/types"
	"gopkg.in/yaml.v3"
)

var (
	version = "1.4.0"
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
	scanCmd.Flags().Int("verify-passes", 1, "Number of LLM verification passes (1=standard, 2+=confirmation loops, max 5)")
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

	// Ecosystem integration flags (Phase 1 new)
	scanCmd.Flags().String("import-bypasses", "", "Import BypassBurrito bypass results to use as payloads")
	scanCmd.Flags().String("export-vinculum", "", "Export findings in Vinculum correlation format")
	scanCmd.Flags().String("export-ariadne", "", "Export findings with attack path context for Ariadne")
	scanCmd.Flags().String("import-container-context", "", "Import Cepheus container posture data to enrich findings")
	scanCmd.Flags().String("import-cloud-audit", "", "Import Nubicustos cloud audit findings to enrich attack surface")

	// WAF detection
	scanCmd.Flags().Bool("detect-waf", false, "Enable WAF detection and bypass payload generation")

	// Callback/OOB detection
	scanCmd.Flags().String("callback-url", "", "External URL for out-of-band vulnerability detection")
	scanCmd.Flags().Int("callback-port", 8888, "HTTP port for callback server")

	// Attack chains
	scanCmd.Flags().Bool("attack-chains", false, "Discover and execute multi-step attack chains")

	// Business rules
	scanCmd.Flags().String("rules-file", "", "Business rules YAML file for targeted security testing")

	// Plugin system
	scanCmd.Flags().String("plugin-dir", "", "Directory containing custom plugin payload/matcher files")
	scanCmd.Flags().StringSlice("plugin-payloads", []string{}, "Custom payload files (JSON/TXT)")
	scanCmd.Flags().StringSlice("plugin-matchers", []string{}, "Custom response matcher files (JSON)")

	// Schema inference
	scanCmd.Flags().String("infer-schema", "", "Infer API schema from traffic and save as OpenAPI spec")

	// Differential analysis
	scanCmd.Flags().StringSlice("diff-auth", []string{}, "Auth contexts for differential analysis (format: name=token)")
	scanCmd.Flags().String("diff-auth-file", "", "YAML file with auth contexts for differential analysis")

	// Stateful session tracking
	scanCmd.Flags().Bool("stateful", false, "Enable stateful session tracking (extract and reuse tokens/IDs)")
	scanCmd.Flags().String("extract-file", "", "YAML file with custom extraction rules")

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

	// Schema inference from traffic (HAR/Burp input)
	inferOutput, _ := cmd.Flags().GetString("infer-schema")
	if inferOutput != "" {
		inferOutput = filepath.Clean(inferOutput)
	}
	if inferOutput != "" && (inputType == types.InputTypeHAR || inputType == types.InputTypeBurp) {
		printInfo("Inferring API schema from captured traffic...")
		inferrer := inference.NewSchemaInferrer(inference.InferenceSettings{
			MinConfidence:    config.Inference.MinConfidence,
			ClusterThreshold: config.Inference.ClusterThreshold,
		})
		for _, ep := range endpoints {
			inferrer.AddRequest(inference.CapturedRequest{
				Method: ep.Method,
				Path:   ep.Path,
				URL:    ep.BaseURL + ep.Path,
			})
		}
		inferredEndpoints, inferErr := inferrer.Infer()
		if inferErr != nil {
			printWarning("Schema inference failed: %v", inferErr)
		} else {
			endpoints = mergeEndpoints(endpoints, inferredEndpoints)
			gen := inference.NewOpenAPIGenerator("Inferred API", "1.0.0", "Auto-inferred from traffic")
			spec, genErr := gen.Generate(inferredEndpoints)
			if genErr == nil {
				if specJSON, jsonErr := spec.ToJSON(); jsonErr == nil {
					if writeErr := os.WriteFile(inferOutput, specJSON, 0600); writeErr != nil {
						printWarning("Failed to save inferred schema: %v", writeErr)
					} else {
						printInfo("Saved inferred OpenAPI spec to: %s", inferOutput)
					}
				}
			}
		}
	}

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

	// Boost concurrency/rate-limit for local targets (e.g., Docker containers)
	applyLocalTargetBoost(cmd, getTarget(endpoints))

	// Load business rules if specified
	rulesFile, _ := cmd.Flags().GetString("rules-file")
	var ruleTestCases []rules.RuleTestCase
	if rulesFile != "" {
		rulesFile = filepath.Clean(rulesFile)
		printInfo("Loading business rules from: %s", rulesFile)
		ruleParser := rules.NewRuleParser()
		ruleSet, ruleErr := ruleParser.ParseFile(rulesFile)
		if ruleErr != nil {
			printWarning("Failed to parse rules file: %v", ruleErr)
		} else if provider != nil {
			translator := rules.NewRuleTranslator(provider)
			testCases, transErr := translator.TranslateRules(ctx, ruleSet.Rules, endpoints)
			if transErr != nil {
				printWarning("Failed to translate rules: %v", transErr)
			} else {
				ruleTestCases = testCases
				printInfo("Generated %d test cases from %d business rules", len(testCases), len(ruleSet.Rules))
			}
		} else {
			printWarning("Business rules require --provider for LLM translation")
		}
	}

	// Load plugins
	pluginDir, _ := cmd.Flags().GetString("plugin-dir")
	pluginPayloadFiles, _ := cmd.Flags().GetStringSlice("plugin-payloads")
	pluginMatcherFiles, _ := cmd.Flags().GetStringSlice("plugin-matchers")
	if pluginDir != "" {
		pluginDir = filepath.Clean(pluginDir)
	}

	var pluginRegistry *plugin.PluginRegistry
	if pluginDir != "" || len(pluginPayloadFiles) > 0 || len(pluginMatcherFiles) > 0 {
		pluginRegistry = plugin.NewRegistry()
		loader := plugin.NewLoader(pluginRegistry)
		for _, pf := range pluginPayloadFiles {
			cleanPath, err := sanitizePluginPath(pf)
			if err != nil {
				printWarning("Skipping plugin payload: %v", err)
				continue
			}
			if err := loader.LoadPayloadFile(cleanPath); err != nil {
				printWarning("Failed to load plugin payloads %s: %v", cleanPath, err)
			}
		}
		for _, mf := range pluginMatcherFiles {
			cleanPath, err := sanitizePluginPath(mf)
			if err != nil {
				printWarning("Skipping plugin matcher: %v", err)
				continue
			}
			if err := loader.LoadMatcherFile(cleanPath); err != nil {
				printWarning("Failed to load plugin matchers %s: %v", cleanPath, err)
			}
		}
		if pluginDir != "" {
			dirLoader := plugin.NewLoader(pluginRegistry)
			jsonFiles, _ := filepath.Glob(filepath.Join(pluginDir, "*.json"))
			for _, f := range jsonFiles {
				cleanPath, err := sanitizePluginPath(f)
				if err != nil {
					printWarning("Skipping plugin file: %v", err)
					continue
				}
				if err := dirLoader.LoadPayloadFile(cleanPath); err != nil {
					printWarning("Failed to load plugin file %s: %v", cleanPath, err)
				}
			}
			txtFiles, _ := filepath.Glob(filepath.Join(pluginDir, "*.txt"))
			for _, f := range txtFiles {
				cleanPath, err := sanitizePluginPath(f)
				if err != nil {
					printWarning("Skipping plugin file: %v", err)
					continue
				}
				if err := dirLoader.LoadPayloadFile(cleanPath); err != nil {
					printWarning("Failed to load plugin file %s: %v", cleanPath, err)
				}
			}
		}
		printInfo("Loaded %d attack plugins, %d response matchers",
			len(pluginRegistry.GetAttackPlugins()), len(pluginRegistry.GetResponseMatchers()))
	}

	// Setup callback server for OOB detection (must happen before payload generation)
	callbackURL, _ := cmd.Flags().GetString("callback-url")
	var callbackServer *callback.CallbackServer
	if callbackURL != "" {
		callbackPort, _ := cmd.Flags().GetInt("callback-port")
		cbSettings := callback.CallbackSettings{
			HTTPPort:    callbackPort,
			ExternalURL: callbackURL,
			Timeout:     config.Callback.Timeout,
		}
		callbackServer = callback.NewCallbackServer(cbSettings)
		if err := callbackServer.Start(ctx); err != nil {
			printWarning("Callback server failed to start: %v", err)
			callbackServer = nil
		} else {
			defer callbackServer.Stop()
			printInfo("Callback server listening on port %d (external: %s)", callbackPort, callbackURL)
		}
	}

	// Import Nubicustos cloud audit if specified
	importCloudFile, _ := cmd.Flags().GetString("import-cloud-audit")
	if importCloudFile != "" {
		importCloudFile = filepath.Clean(importCloudFile)
		cloudImport, cloudErr := importer.LoadNubicustosFindings(importCloudFile)
		if cloudErr != nil {
			printWarning("Failed to load Nubicustos cloud audit: %v", cloudErr)
		} else {
			endpoints = importer.EnrichEndpointsFromCloud(cloudImport, endpoints)
			printInfo("Enriched endpoints with %d cloud findings from Nubicustos", len(cloudImport.Findings))
		}
	}

	// Generate payloads
	printInfo("Generating payloads...")
	if config.Attacks.UseLLMPayloads && provider != nil {
		printInfo("Dynamic LLM payload generation enabled (concurrency: %d)", config.Attacks.LLMConcurrency)
	}
	payloadGen := payloads.NewGenerator(provider, config.Attacks, config.UserContext)

	// Pass callback URLs to blind payload generator
	if callbackServer != nil {
		token := callbackServer.RegisterCallback("blind-payloads", "blind", types.Endpoint{}, "")
		httpCB := callbackServer.GetHTTPCallback(token)
		dnsCB := callbackServer.GetDNSCallback(token)
		payloadGen.SetBlindCallbacks(httpCB, dnsCB)
		printInfo("Blind payloads will use callback URL: %s", httpCB)
	}
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
	// Append fuzz requests from business rules
	if len(ruleTestCases) > 0 {
		ruleFuzzReqs := rulesToFuzzRequests(ruleTestCases, endpoints)
		fuzzRequests = append(fuzzRequests, ruleFuzzReqs...)
	}

	// Import BypassBurrito bypasses if specified
	importBypassesFile, _ := cmd.Flags().GetString("import-bypasses")
	if importBypassesFile != "" {
		importBypassesFile = filepath.Clean(importBypassesFile)
		bypassImport, bypassErr := importer.LoadBurritoBypasses(importBypassesFile)
		if bypassErr != nil {
			printWarning("Failed to load BypassBurrito bypasses: %v", bypassErr)
		} else {
			bypassReqs := importer.BypassesToFuzzRequests(bypassImport, endpoints)
			if len(bypassReqs) > 0 {
				// Prepend bypass payloads for priority execution
				fuzzRequests = append(bypassReqs, fuzzRequests...)
				printInfo("Imported %d bypass payloads from BypassBurrito", len(bypassReqs))
			}
		}
	}

	printInfo("Generated %d fuzz requests", len(fuzzRequests))

	// Setup checkpoint manager
	resumePath, _ := cmd.Flags().GetString("resume")
	checkpointPath, _ := cmd.Flags().GetString("checkpoint")
	checkpointInterval, _ := cmd.Flags().GetDuration("checkpoint-interval")

	var cpManager *checkpoint.Manager
	var restoredFindings []types.Finding
	if resumePath != "" {
		cpManager, err = checkpoint.LoadAndResume(resumePath)
		if err != nil {
			return fmt.Errorf("failed to resume from checkpoint: %w", err)
		}
		restoredFindings = cpManager.GetFindings()
		if len(restoredFindings) > 0 {
			printInfo("Restored %d findings from checkpoint", len(restoredFindings))
		}
		fuzzRequests = cpManager.FilterPendingRequests(fuzzRequests, func(r payloads.FuzzRequest) string {
			return r.Endpoint.Method + ":" + r.Endpoint.Path + ":" + r.Payload.Value
		})
		printInfo("Resumed from checkpoint: %d requests remaining", len(fuzzRequests))
	} else {
		cpConfig := checkpoint.DefaultManagerConfig()
		if checkpointPath != "" {
			cpConfig.FilePath = checkpointPath
		}
		if checkpointInterval > 0 {
			cpConfig.Interval = checkpointInterval
		}
		cpManager = checkpoint.NewManager(cpConfig)
		cpManager.Initialize(uuid.New().String(), inputFile, string(inputType), getTarget(endpoints), nil)
	}
	cpManager.StartAutoSave()
	defer cpManager.StopAutoSave()

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

	// Setup WAF detector
	detectWAF, _ := cmd.Flags().GetBool("detect-waf")
	var wafDetector *waf.WAFDetector
	if detectWAF {
		wafDetector = waf.NewWAFDetector(provider, config.WAF.Threshold, config.WAF.Bypass)
		printInfo("WAF detection enabled (threshold: %d consecutive blocks)", config.WAF.Threshold)
	}

	// Setup differential analysis
	diffAuthArgs, _ := cmd.Flags().GetStringSlice("diff-auth")
	diffAuthFile, _ := cmd.Flags().GetString("diff-auth-file")
	var diffContexts []types.AuthContext

	if len(diffAuthArgs) > 0 {
		diffContexts = detector.ParseAuthContexts(diffAuthArgs)
	} else if diffAuthFile != "" {
		data, readErr := os.ReadFile(filepath.Clean(diffAuthFile))
		if readErr != nil {
			printWarning("Failed to read diff-auth-file: %v", readErr)
		} else {
			if yamlErr := yaml.Unmarshal(data, &diffContexts); yamlErr != nil {
				printWarning("Failed to parse diff-auth-file: %v", yamlErr)
			}
		}
	}

	var diffAnalyzer *detector.DifferentialAnalyzer
	var multiAuthExec *fuzzer.MultiAuthExecutor
	if len(diffContexts) >= 2 {
		diffAnalyzer = detector.NewDifferentialAnalyzer(diffContexts)
		multiAuthExec = fuzzer.NewMultiAuthExecutor(engine, diffContexts)
		printInfo("Differential analysis enabled with %d auth contexts", len(diffContexts))
	}

	// Setup stateful session tracking
	enableStateful, _ := cmd.Flags().GetBool("stateful")
	var stateTracker *fuzzer.StateTracker
	var extractor *fuzzer.Extractor

	if enableStateful {
		stateTracker = fuzzer.NewStateTracker()
		extractor = fuzzer.NewExtractor(stateTracker, true) // autoExtract=true

		extractFile, _ := cmd.Flags().GetString("extract-file")
		if extractFile != "" {
			data, readErr := os.ReadFile(filepath.Clean(extractFile))
			if readErr != nil {
				printWarning("Failed to read extract-file: %v", readErr)
			} else if yamlErr := extractor.LoadRulesFromYAML(data); yamlErr != nil {
				printWarning("Failed to parse extract-file: %v", yamlErr)
			}
		}
		printInfo("Stateful session tracking enabled (auto-extraction: on)")
	}

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

	// Pre-extract state from baseline responses
	if stateTracker != nil {
		for _, ep := range endpoints {
			baseline, _ := engine.GetBaseline(ctx, ep)
			if baseline != nil {
				extractor.ExtractFromResponse(baseline, ep.Method+":"+ep.Path)
			}
		}
		vars := stateTracker.GetAllVariables()
		if len(vars) > 0 {
			printInfo("Extracted %d state variables from baselines", len(vars))
		}
	}

	// Substitute state variables into payloads
	if stateTracker != nil {
		for i := range fuzzRequests {
			fuzzRequests[i].Payload.Value = stateTracker.SubstituteVariables(fuzzRequests[i].Payload.Value)
			if fuzzRequests[i].Endpoint.Path != "" {
				fuzzRequests[i].Endpoint.Path = stateTracker.SubstituteVariables(fuzzRequests[i].Endpoint.Path)
			}
		}
	}

	// Separate WebSocket requests from HTTP requests
	httpRequests, wsRequests := fuzzer.FilterWebSocketRequests(fuzzRequests)
	if len(wsRequests) > 0 {
		printInfo("Separated %d WebSocket requests from %d HTTP requests", len(wsRequests), len(httpRequests))
		fuzzRequests = httpRequests
	}

	// Check if BOLA attacks are enabled without diff-auth
	if len(diffContexts) < 2 {
		hasBOLA := false
		for _, ep := range endpoints {
			for _, a := range ep.SuggestedAttacks {
				if a.Type == types.AttackBOLA || a.Type == types.AttackIDOR {
					hasBOLA = true
					break
				}
			}
			if hasBOLA {
				break
			}
		}
		if hasBOLA {
			printWarning("BOLA/IDOR attacks enabled without --diff-auth. For best results, provide two auth contexts: --diff-auth 'user1=Bearer token1' --diff-auth 'user2=Bearer token2'")
		}
	}

	// Run fuzzing
	printInfo("Starting scan...")
	startTime := time.Now()

	var findings []types.Finding
	findings = append(findings, passiveFindings...)
	if resumePath != "" && cpManager != nil {
		findings = append(findings, restoredFindings...)
	}

	processedCount := 0
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Console dedup: prevent printing the same finding hundreds of times
	consoleSeen := make(map[string]bool)
	consoleSuppressed := 0
	massAssignAuthBlocked := 0

	if multiAuthExec != nil {
		// Differential mode: fuzz with all auth contexts
		diffEndpoints := make(map[string]struct{})
		multiResults := multiAuthExec.FuzzWithContexts(ctx, fuzzRequests)
		for result := range multiResults {
			processedCount++
			endpointKey := result.Endpoint.Method + ":" + result.Endpoint.Path
			diffEndpoints[endpointKey] = struct{}{}

			for ctxName, fuzzResult := range result.Results {
				// Update stats
				respSize := int64(0)
				if fuzzResult.Response != nil {
					respSize = fuzzResult.Response.ContentLength
				}
				scanStats.Update(fuzzResult.Duration, fuzzResult.Error == nil, respSize)

				// Standard analysis per context
				var baseline *types.HTTPResponse
				if fuzzResult.Error == nil {
					baseline, _ = engine.GetBaseline(ctx, fuzzResult.Request.Endpoint)
				}
				resultFindings := responseAnalyzer.AnalyzeResult(fuzzResult, baseline)
				findings = append(findings, resultFindings...)

				// Store response for differential comparison
				if fuzzResult.Response != nil {
					diffAnalyzer.StoreResponse(endpointKey, ctxName, fuzzResult.Response)
				}

				// Extract state from responses
				if stateTracker != nil && fuzzResult.Response != nil {
					extractor.ExtractFromResponse(fuzzResult.Response, endpointKey)
				}

				// Print findings as they're discovered (with dedup)
				for _, f := range resultFindings {
					key := consoleDedupKey(f)
					if !consoleSeen[key] {
						consoleSeen[key] = true
						printFindingWithVerbose(f, verbose)
					} else {
						consoleSuppressed++
					}
				}
			}

			// Print progress
			if processedCount%50 == 0 {
				printProgress(processedCount, len(fuzzRequests))
			}
		}

		// Run differential analysis across all endpoints
		printInfo("Analyzing differential responses...")
		for endpointKey := range diffEndpoints {
			parts := strings.SplitN(endpointKey, ":", 2)
			method, path := parts[0], parts[1]
			anomalies := diffAnalyzer.AnalyzeEndpoint(endpointKey)
			for _, anomaly := range anomalies {
				findings = append(findings, anomaly.ToFinding(path, method))
			}
		}
	} else {
		// Standard mode
		results := engine.Fuzz(ctx, fuzzRequests)

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

			// Apply plugin matchers
			if pluginRegistry != nil && result.Response != nil && result.ActualRequest != nil {
				for _, matcher := range pluginRegistry.GetResponseMatchers() {
					matchResult, matchErr := matcher.Match(ctx, result.Response, result.ActualRequest)
					if matchErr == nil && matchResult != nil && matchResult.Matched {
						resultFindings = append(resultFindings, types.Finding{
							ID:          uuid.New().String(),
							Type:        "plugin_match",
							Severity:    matchResult.Severity,
							Confidence:  matchResult.Confidence,
							Title:       matchResult.Title,
							Description: matchResult.Description,
							CWE:         matchResult.CWE,
							Endpoint:    result.Request.Endpoint.Path,
							Method:      result.Request.Endpoint.Method,
						})
					}
				}
			}

			findings = append(findings, resultFindings...)

			// WAF detection
			if wafDetector != nil && result.Response != nil {
				detected := wafDetector.AnalyzeResponse(result.Response, result.Request.Endpoint.Path, result.Request.Payload.Value)
				if detected != nil && wafDetector.ShouldTriggerBypass() {
					printWarning("WAF detected: %s (confidence: %.0f%%)", detected.Name, detected.Confidence*100)
					wafDetector.ResetBlockCount()
				}
			}

			// Extract state from responses
			if stateTracker != nil && result.Response != nil {
				endpointKey := result.Request.Endpoint.Method + ":" + result.Request.Endpoint.Path
				extractor.ExtractFromResponse(result.Response, endpointKey)
			}

			// Record checkpoint progress
			if cpManager != nil {
				fingerprint := result.Request.Endpoint.Method + ":" + result.Request.Endpoint.Path + ":" + result.Request.Payload.Value
				cpManager.RecordCompletion(fingerprint)
				for _, f := range resultFindings {
					cpManager.AddFinding(f)
				}
			}

			// Print progress
			if processedCount%100 == 0 {
				printProgress(processedCount, len(fuzzRequests))
			}

			// Track mass assignment auth blocks
			if result.Request.Payload.Type == types.AttackMassAssignment &&
				result.Response != nil &&
				(result.Response.StatusCode == 401 || result.Response.StatusCode == 403) {
				massAssignAuthBlocked++
			}

			// Print findings as they're discovered (with dedup)
			for _, f := range resultFindings {
				key := consoleDedupKey(f)
				if !consoleSeen[key] {
					consoleSeen[key] = true
					printFindingWithVerbose(f, verbose)
				} else {
					consoleSuppressed++
				}
			}
		}
	}

	// Run WebSocket fuzzer for WS-tagged requests
	if len(wsRequests) > 0 {
		printInfo("Fuzzing %d WebSocket endpoints...", len(wsRequests))
		wsFuzzer := fuzzer.NewWebSocketFuzzer(*config)
		wsResults := wsFuzzer.Fuzz(ctx, wsRequests)
		for result := range wsResults {
			processedCount++

			// Update stats
			respSize := int64(0)
			if result.Response != nil {
				respSize = result.Response.ContentLength
			}
			scanStats.Update(result.Duration, result.Error == nil, respSize)

			// Analyze result
			var baseline *types.HTTPResponse
			resultFindings := responseAnalyzer.AnalyzeResult(result, baseline)
			findings = append(findings, resultFindings...)

			for _, f := range resultFindings {
				key := consoleDedupKey(f)
				if !consoleSeen[key] {
					consoleSeen[key] = true
					printFindingWithVerbose(f, verbose)
				} else {
					consoleSuppressed++
				}
			}
		}
	}

	endTime := time.Now()

	if consoleSuppressed > 0 {
		printInfo("Suppressed %d duplicate console findings (all retained in report)", consoleSuppressed)
	}
	if massAssignAuthBlocked > 10 {
		printWarning("Mass assignment: %d payloads blocked by auth (401/403). Use --auth-header for better coverage.", massAssignAuthBlocked)
	}

	// Collect out-of-band callback results
	if callbackServer != nil {
		printInfo("Collecting out-of-band callback results...")
		time.Sleep(config.Callback.Timeout)
		for _, cb := range callbackServer.GetReceivedCallbacks() {
			findings = append(findings, cb.ToFinding())
		}
	}

	// Execute attack chains
	enableChains, _ := cmd.Flags().GetBool("attack-chains")
	if enableChains && provider != nil {
		printInfo("Analyzing endpoint relationships for attack chains...")
		chainAnalyzer := chains.NewChainAnalyzer(provider)
		discoveredChains, chainErr := chainAnalyzer.AnalyzeEndpoints(ctx, endpoints)
		if chainErr != nil {
			printWarning("Chain analysis failed: %v", chainErr)
		} else if len(discoveredChains) > 0 {
			printInfo("Discovered %d attack chains, executing...", len(discoveredChains))
			executor := chains.NewExecutor(engine, chains.ExecutorConfig{
				MaxDepth: 5,
				Timeout:  5 * time.Minute,
			})
			chainResults := executor.ExecuteAll(ctx, discoveredChains)
			for _, cr := range chainResults {
				findings = append(findings, cr.Findings...)
			}
		}
	}

	// Finalize stats
	scanStats.Finalize(endTime.Sub(startTime))

	// Apply combined filtering (noise, confidence, deduplication)
	combinedFilter := detector.NewCombinedFilter(config.Filter)
	findings = combinedFilter.Filter(findings)

	// LLM-powered verification
	verifyEnabled, _ := cmd.Flags().GetBool("verify")
	if verifyEnabled && provider != nil {
		printInfo("Verifying findings with LLM analysis...")
		llmVerifier := verify.NewLLMVerifier(provider, config.Verify, engine, responseAnalyzer)
		verifiedFindings, followUpFindings, verifyErr := llmVerifier.VerifyFindings(ctx, findings)
		if verifyErr != nil {
			printWarning("LLM verification encountered errors: %v", verifyErr)
		}
		findings = verifiedFindings
		if len(followUpFindings) > 0 {
			printInfo("LLM verification discovered %d additional findings", len(followUpFindings))
			followUpFindings = combinedFilter.Filter(followUpFindings)
			findings = append(findings, followUpFindings...)
		}

		// Multi-pass confirmation loop
		verifyPasses, _ := cmd.Flags().GetInt("verify-passes")
		if verifyPasses > 5 {
			printWarning("--verify-passes capped at 5 (requested %d)", verifyPasses)
			verifyPasses = 5
		}
		if verifyPasses > 1 {
			printInfo("Running %d confirmation passes...", verifyPasses-1)
			confirmedFindings, confirmErr := llmVerifier.ConfirmFindings(ctx, findings, verifyPasses)
			if confirmErr != nil {
				printWarning("Confirmation pass errors: %v", confirmErr)
			} else {
				findings = confirmedFindings
			}
		}
	} else if verifyEnabled && provider == nil {
		printWarning("--verify requires --provider for LLM verification; falling back to HTTP verification")
		httpVerifier := verify.NewVerifier(verify.DefaultVerifyConfig())
		results := httpVerifier.VerifyAll(ctx, findings)
		findings = verify.FilterVerified(results)
	}

	// Warn if --verify-passes set without --verify
	if !verifyEnabled {
		if vp, _ := cmd.Flags().GetInt("verify-passes"); vp > 1 {
			printWarning("--verify-passes has no effect without --verify flag")
		}
	}

	// Enrich findings with container context if specified
	importContainerFile, _ := cmd.Flags().GetString("import-container-context")
	if importContainerFile != "" {
		importContainerFile = filepath.Clean(importContainerFile)
		cepheusImport, cephErr := importer.LoadCepheusFindings(importContainerFile)
		if cephErr != nil {
			printWarning("Failed to load Cepheus container context: %v", cephErr)
		} else {
			findings = importer.EnrichFindingsWithContainerContext(cepheusImport, findings)
			printInfo("Enriched %d findings with container context from Cepheus (%d containers, %d escape paths)",
				len(findings), len(cepheusImport.Containers), len(cepheusImport.EscapePaths))
		}
	}

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

	// Export findings in Vinculum correlation format
	vinculumFile, _ := cmd.Flags().GetString("export-vinculum")
	if vinculumFile != "" {
		if err := reporter.ExportVinculum(scanResult, vinculumFile); err != nil {
			printWarning("Failed to export Vinculum findings: %v", err)
		} else {
			printInfo("Vinculum correlation findings exported to: %s", vinculumFile)
		}
	}

	// Export findings with attack path context for Ariadne
	ariadneFile, _ := cmd.Flags().GetString("export-ariadne")
	if ariadneFile != "" {
		if err := reporter.ExportAriadne(scanResult, ariadneFile); err != nil {
			printWarning("Failed to export Ariadne attack paths: %v", err)
		} else {
			printInfo("Ariadne attack path findings exported to: %s", ariadneFile)
		}
	}

	// Generate report
	outputFile, _ := cmd.Flags().GetString("output")
	outputFormat, _ := cmd.Flags().GetString("format")
	noColor, _ := cmd.Flags().GetBool("no-color")

	// Handle text format specially - print to stdout if no output file specified
	if (outputFormat == "text" || outputFormat == "txt") && outputFile == "" {
		rep, err := reporter.NewReporterWithColorControl(outputFormat, reporter.ReportOptions{IncludeRaw: true, IncludeConfig: true, Version: version}, noColor)
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

	rep, err := reporter.NewReporterWithColorControl(outputFormat, reporter.ReportOptions{IncludeRaw: true, IncludeConfig: true, Version: version}, noColor)
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

// isLocalTarget returns true if the target URL points to a local address
// (localhost, 127.0.0.0/8, ::1, 0.0.0.0, or private Docker networks).
func isLocalTarget(target string) bool {
	if target == "" || target == "unknown" {
		return false
	}
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

const (
	localConcurrency = 50
	localRateLimit   = 100.0
)

// applyLocalTargetBoost increases concurrency and rate limit for local targets
// unless the user explicitly set those flags.
func applyLocalTargetBoost(cmd *cobra.Command, target string) {
	if !isLocalTarget(target) {
		return
	}
	boosted := false
	if !cmd.Flags().Changed("concurrency") {
		config.Scan.Concurrency = localConcurrency
		boosted = true
	}
	if !cmd.Flags().Changed("rate-limit") {
		config.Scan.RateLimit = localRateLimit
		boosted = true
	}
	if boosted {
		printInfo("Local target detected (%s) — boosted to concurrency=%d, rate-limit=%.0f rps",
			target, config.Scan.Concurrency, config.Scan.RateLimit)
	}
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

// consoleDedupKey generates a dedup key for real-time console output.
// Mirrors the logic in filter.go's dedupeKey: noise types dedupe by
// METHOD:ENDPOINT:TYPE, vulnerability types keep the parameter.
func consoleDedupKey(f types.Finding) string {
	switch f.Type {
	case "server_error", "error_triggered", "data_leak", "information_disclosure",
		"missing_security_headers", "stack_trace_exposure", "file_path_disclosure",
		"python_error", "database_error", "response_anomaly", "rate_limit_missing",
		"enumeration":
		return f.Method + ":" + f.Endpoint + ":" + f.Type
	default:
		return f.Method + ":" + f.Endpoint + ":" + f.Type + ":" + f.Parameter
	}
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

func mergeEndpoints(existing, inferred []types.Endpoint) []types.Endpoint {
	seen := make(map[string]bool)
	for _, ep := range existing {
		seen[ep.Method+":"+ep.Path] = true
	}
	merged := make([]types.Endpoint, len(existing))
	copy(merged, existing)
	for _, ep := range inferred {
		key := ep.Method + ":" + ep.Path
		if !seen[key] {
			merged = append(merged, ep)
			seen[key] = true
		}
	}
	return merged
}

func rulesToFuzzRequests(testCases []rules.RuleTestCase, endpoints []types.Endpoint) []payloads.FuzzRequest {
	endpointMap := make(map[string]types.Endpoint)
	for _, ep := range endpoints {
		endpointMap[ep.Method+":"+ep.Path] = ep
	}

	var reqs []payloads.FuzzRequest
	for _, tc := range testCases {
		// Build fuzz requests from the action step
		step := tc.ActionStep
		key := step.Method + ":" + step.Endpoint
		ep, found := endpointMap[key]
		if !found {
			ep = types.Endpoint{
				Method: step.Method,
				Path:   step.Endpoint,
			}
		}

		payload := payloads.Payload{
			Type:        "business_rule",
			Category:    "business_rule",
			Description: tc.Description,
			Metadata: map[string]string{
				"source":  "business-rule",
				"rule_id": tc.RuleID,
			},
		}

		// Use query params or body as payload value
		if len(step.Body) > 0 {
			bodyBytes, _ := json.Marshal(step.Body)
			payload.Value = string(bodyBytes)
		} else if len(step.QueryParams) > 0 {
			var parts []string
			for k, v := range step.QueryParams {
				parts = append(parts, k+"="+v)
			}
			payload.Value = strings.Join(parts, "&")
		}

		reqs = append(reqs, payloads.FuzzRequest{
			Endpoint: ep,
			Payload:  payload,
			Position: "body",
		})
	}
	return reqs
}

func getConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".config", "indago")
}

func sanitizePluginPath(path string) (string, error) {
	// Check original path for traversal before cleaning resolves it away
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("plugin path %q contains directory traversal", path)
	}
	cleaned := filepath.Clean(path)
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return "", fmt.Errorf("plugin path %q: %w", path, err)
	}
	// Verify the resolved path is within the current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("cannot determine working directory: %w", err)
	}
	if !strings.HasPrefix(abs, cwd+string(filepath.Separator)) && abs != cwd {
		return "", fmt.Errorf("plugin path %q resolves outside working directory", path)
	}
	return abs, nil
}
