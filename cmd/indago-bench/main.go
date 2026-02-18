// Package main is the entry point for the Indago benchmark loop orchestrator.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/su1ph3r/indago/internal/benchmark"
	"github.com/su1ph3r/indago/internal/llm"
	"github.com/su1ph3r/indago/internal/parser"
	"github.com/su1ph3r/indago/pkg/types"
)

var version = "0.1.0"

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "indago-bench",
	Short: "Indago Benchmark Loop - iteratively improve detection",
	Long: `Indago Benchmark Loop runs Indago against a known-vulnerable API (VAmPI),
measures detection gaps, uses LLMs to propose general-purpose improvements,
applies them, and repeats until convergence (100% recall, zero false positives).`,
	Version: version,
	RunE:    runBench,
}

func init() {
	rootCmd.Flags().String("vampi-url", "", "VAmPI base URL (default: auto-start Docker on :5002)")
	rootCmd.Flags().Int("vampi-port", 5002, "Host port for VAmPI Docker container")
	rootCmd.Flags().String("provider", "", "LLM provider for Indago scanning (openai, anthropic, ollama, lmstudio)")
	rootCmd.Flags().String("improvement-provider", "anthropic", "LLM provider for code improvements")
	rootCmd.Flags().String("improvement-provider-local", "", "Local LLM provider for council (e.g., lmstudio)")
	rootCmd.Flags().String("api-key", "", "API key for improvement LLM provider")
	rootCmd.Flags().String("llm-url", "", "Base URL for local LLM")
	rootCmd.Flags().String("model", "", "Model for improvement LLM")
	rootCmd.Flags().Int("max-iterations", 20, "Maximum improvement iterations")
	rootCmd.Flags().String("ground-truth", "testdata/vampi/ground_truth.yaml", "Path to ground truth YAML")
	rootCmd.Flags().String("vampi-spec", "testdata/vampi/openapi3.yml", "Path to VAmPI OpenAPI spec")
	rootCmd.Flags().String("convergence-file", "testdata/vampi/convergence.jsonl", "Path to convergence tracking file")
	rootCmd.Flags().Bool("skip-docker", false, "Skip Docker management (use --vampi-url instead)")
	rootCmd.Flags().Bool("no-commit", false, "Skip git commits after improvements")
	rootCmd.Flags().Bool("scan-only", false, "Run scan and evaluate only, skip improvement phase")
	rootCmd.Flags().Int("concurrency", 1, "Scan concurrency (number of parallel requests)")
	rootCmd.Flags().Float64("rate-limit", 5, "Scan rate limit (requests per second)")
}

func runBench(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupts
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		printWarning("\nInterrupted, cleaning up...")
		cancel()
	}()

	// Parse flags
	maxIterations, _ := cmd.Flags().GetInt("max-iterations")
	groundTruthPath, _ := cmd.Flags().GetString("ground-truth")
	specPath, _ := cmd.Flags().GetString("vampi-spec")
	convergencePath, _ := cmd.Flags().GetString("convergence-file")
	scanProvider, _ := cmd.Flags().GetString("provider")
	skipDocker, _ := cmd.Flags().GetBool("skip-docker")
	noCommit, _ := cmd.Flags().GetBool("no-commit")
	vampiPort, _ := cmd.Flags().GetInt("vampi-port")

	projectRoot, err := findProjectRoot()
	if err != nil {
		return fmt.Errorf("find project root: %w", err)
	}

	// Resolve relative paths
	groundTruthPath = resolvePath(projectRoot, groundTruthPath)
	specPath = resolvePath(projectRoot, specPath)
	convergencePath = resolvePath(projectRoot, convergencePath)

	// Load ground truth
	gt, err := benchmark.LoadGroundTruth(groundTruthPath)
	if err != nil {
		return fmt.Errorf("load ground truth: %w", err)
	}
	printInfo("Loaded %d ground truth vulnerabilities", len(gt.Vulnerabilities))

	scanOnly, _ := cmd.Flags().GetBool("scan-only")

	// Setup improvement LLM provider(s) — optional for scan-only mode
	var imp *benchmark.Improver
	if !scanOnly {
		primaryProvider, provErr := setupImprovementProvider(cmd)
		if provErr != nil {
			printWarning("No improvement provider configured: %v", provErr)
			printWarning("Running in scan-only mode (no code improvements)")
			scanOnly = true
		} else {
			var localProvider llm.Provider
			localProviderName, _ := cmd.Flags().GetString("improvement-provider-local")
			if localProviderName != "" {
				localProvider, err = setupLocalProvider(cmd, localProviderName)
				if err != nil {
					printWarning("Local provider setup failed: %v (continuing with primary only)", err)
				}
			}
			imp = benchmark.NewImprover(primaryProvider, localProvider, projectRoot)
		}
	}
	tracker := benchmark.NewConvergenceTracker(convergencePath)

	// VAmPI setup
	vampiURL, _ := cmd.Flags().GetString("vampi-url")
	var vampi *benchmark.VAmPISetup
	if !skipDocker && vampiURL == "" {
		vampi = benchmark.NewVAmPISetup(vampiPort)
		defer vampi.Stop()
	}

	printBanner()

	// Create timestamped results directory for this run
	runTimestamp := time.Now().Format("2006-01-02T15-04-05")
	resultsDir := filepath.Join(projectRoot, "testdata/vampi/results", runTimestamp)
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return fmt.Errorf("create results directory: %w", err)
	}
	printInfo("Scan results will be stored in %s", resultsDir)

	// Main iteration loop
	for iteration := 1; iteration <= maxIterations; iteration++ {
		if ctx.Err() != nil {
			printWarning("Cancelled")
			break
		}

		printHeader(fmt.Sprintf("ITERATION %d / %d", iteration, maxIterations))

		// Step 1: Start fresh VAmPI
		var tokens *benchmark.VAmPITokens
		if vampi != nil {
			printInfo("Starting fresh VAmPI container...")
			tokens, err = vampi.Start()
			if err != nil {
				return fmt.Errorf("iteration %d: start VAmPI: %w", iteration, err)
			}
			vampiURL = vampi.BaseURL
		} else if vampiURL != "" {
			// External VAmPI: register users manually
			ext := benchmark.NewVAmPISetup(vampiPort)
			ext.BaseURL = vampiURL
			tokens, err = ext.Start()
			if err != nil {
				printWarning("User setup on external VAmPI failed: %v", err)
			}
		}

		// Step 2: Build Indago from source
		printInfo("Building Indago from source...")
		indagoBin := filepath.Join(projectRoot, "indago-bench-bin")
		if err := buildIndago(projectRoot, indagoBin); err != nil {
			return fmt.Errorf("iteration %d: build failed: %w", iteration, err)
		}

		// Step 3: Run Indago scan
		outputPath := filepath.Join(resultsDir, fmt.Sprintf("scan-iter-%d.json", iteration))
		logPath := filepath.Join(resultsDir, fmt.Sprintf("requests-iter-%d.jsonl", iteration))

		concurrency, _ := cmd.Flags().GetInt("concurrency")
		rateLimit, _ := cmd.Flags().GetFloat64("rate-limit")

		printInfo("Running Indago scan (concurrency=%d, rate-limit=%.0f)...", concurrency, rateLimit)
		scanArgs := buildScanArgs(tokens, specPath, outputPath, logPath, vampiURL, scanProvider, concurrency, rateLimit)

		// Start VAmPI watchdog to auto-restart if it hangs
		var stopWatchdog func()
		if vampi != nil {
			stopWatchdog = vampi.StartWatchdog(10 * time.Second)
		}

		if err := runIndago(ctx, indagoBin, scanArgs); err != nil {
			printWarning("Scan had errors: %v", err)
			// Continue anyway — partial results may still be useful
		}

		// Stop the watchdog
		if stopWatchdog != nil {
			stopWatchdog()
		}

		// Step 4: Parse scan results
		findings, err := loadScanResults(outputPath)
		if err != nil {
			printWarning("Failed to load scan results: %v (using empty findings)", err)
			findings = nil
		}
		printInfo("Scan produced %d findings", len(findings))

		// Step 5: Evaluate against ground truth
		evalResult := benchmark.Evaluate(gt, findings)
		printEvaluation(evalResult)

		// Step 6: Track metrics
		// Parse spec to get the list of endpoints Indago would scan
		specEndpoints := parseSpecEndpoints(specPath)
		scannedEndpoints := benchmark.ExtractScannedEndpoints(logPath, findings, specEndpoints)
		// Build false positive details for convergence tracking
		var fpDetails []benchmark.FPSummary
		for _, fp := range evalResult.FalsePositives {
			fpDetails = append(fpDetails, benchmark.FPSummary{
				Type:      fp.Type,
				Endpoint:  fp.Endpoint,
				Method:    fp.Method,
				Parameter: fp.Parameter,
				Severity:  fp.Severity,
				Title:     fp.Title,
			})
		}

		rec := benchmark.IterationRecord{
			Iteration:            iteration,
			Recall:               evalResult.Recall,
			Precision:            evalResult.Precision,
			F1:                   evalResult.F1,
			FalsePositives:       len(evalResult.FalsePositives),
			FalseNegatives:       len(evalResult.FalseNegatives),
			TruePositives:        len(evalResult.TruePositives),
			AvgConfidence:        evalResult.AvgConfidence,
			TotalFindings:        evalResult.TotalFindings,
			FalsePositiveDetails: fpDetails,
		}

		// Step 7: Check convergence
		if tracker.IsConverged(rec) {
			rec.Converged = true
			tracker.Append(rec)
			printConvergence(iteration, evalResult)
			cleanupIteration(vampi, indagoBin)
			break
		}

		// Step 8: Check stall
		if tracker.IsStalled(3) {
			printWarning("Recall stalled for 3 iterations — consider manual intervention")
		}

		// Step 9: Gap analysis
		printInfo("Analyzing detection gaps...")
		gaps := benchmark.AnalyzeGaps(evalResult.FalseNegatives, findings, logPath, scannedEndpoints)
		for _, g := range gaps {
			printGap(g)
		}

		// Step 10-12: Propose and apply improvements (skip in scan-only mode)
		if !scanOnly && imp != nil {
			printInfo("Generating improvement proposals...")
			proposals, propErr := imp.Propose(ctx, evalResult, gaps)
			if propErr != nil {
				printWarning("Improvement proposal failed: %v", propErr)
				tracker.Append(rec)
				cleanupIteration(vampi, indagoBin)
				continue
			}
			printInfo("Received %d improvement proposals", len(proposals))

			printInfo("Applying improvements...")
			applied := imp.Apply(proposals)
			var appliedNames []string
			for _, p := range applied {
				if p.Applied {
					printSuccess("Applied: [%s] %s — %s", p.Category, p.FilePath, p.Rationale)
					appliedNames = append(appliedNames, fmt.Sprintf("%s:%s", p.Category, filepath.Base(p.FilePath)))
				} else {
					printWarning("Skipped: [%s] %s — %s", p.Category, p.FilePath, p.Error)
				}
			}
			rec.ImprovementsUsed = appliedNames

			if !noCommit && len(appliedNames) > 0 {
				commitMsg := fmt.Sprintf("bench: iteration %d - %s", iteration, strings.Join(appliedNames, ", "))
				if err := gitCommit(projectRoot, commitMsg); err != nil {
					printWarning("Git commit failed: %v", err)
				}
			}
		}

		tracker.Append(rec)

		// Step 13: Cleanup iteration
		cleanupIteration(vampi, indagoBin)
		printInfo("Results preserved: %s", resultsDir)
	}

	// Final report
	printFinalReport(tracker)

	return nil
}

func buildScanArgs(tokens *benchmark.VAmPITokens, specPath, outputPath, logPath, baseURL, provider string, concurrency int, rateLimit float64) []string {
	args := []string{
		"scan",
		"--spec", specPath,
		"--url", baseURL,
		"--format", "json",
		"--output", outputPath,
		"--log-requests", logPath,
		"--passive-checks",
		"--no-ssl-verify",
		"--timeout", "30s",
		"--rate-limit", fmt.Sprintf("%.0f", rateLimit),
		"--concurrency", fmt.Sprintf("%d", concurrency),
	}

	if tokens != nil {
		args = append(args, "--auth-header", "Bearer "+tokens.User1Token)
		args = append(args,
			"--diff-auth", fmt.Sprintf("%s=Bearer %s", tokens.User1Name, tokens.User1Token),
			"--diff-auth", fmt.Sprintf("%s=Bearer %s", tokens.User2Name, tokens.User2Token),
		)
	}

	if provider != "" {
		args = append(args, "--provider", provider)
		args = append(args, "--use-llm-payloads")
	}

	return args
}

func buildIndago(projectRoot, outputBin string) error {
	cmd := exec.Command("go", "build", "-o", outputBin, "./cmd/indago")
	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, string(output))
	}
	return nil
}

func runIndago(ctx context.Context, bin string, args []string) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func loadScanResults(path string) ([]types.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var result types.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse scan results: %w", err)
	}

	return result.Findings, nil
}

func gitCommit(projectRoot, message string) error {
	// Stage all modified Go files
	cmd := exec.Command("git", "add", "-A", "internal/", "pkg/")
	cmd.Dir = projectRoot
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git add: %w\n%s", err, string(output))
	}

	cmd = exec.Command("git", "commit", "-m", message)
	cmd.Dir = projectRoot
	if output, err := cmd.CombinedOutput(); err != nil {
		// No changes to commit is not an error
		if strings.Contains(string(output), "nothing to commit") {
			return nil
		}
		return fmt.Errorf("git commit: %w\n%s", err, string(output))
	}
	return nil
}

func cleanupIteration(vampi *benchmark.VAmPISetup, indagoBin string) {
	if vampi != nil {
		vampi.Stop()
	}
	os.Remove(indagoBin)
}

func parseSpecEndpoints(specPath string) []types.Endpoint {
	p, err := parser.NewParser(specPath, "")
	if err != nil {
		return nil
	}
	endpoints, err := p.Parse()
	if err != nil {
		return nil
	}
	return endpoints
}

func setupImprovementProvider(cmd *cobra.Command) (llm.Provider, error) {
	name, _ := cmd.Flags().GetString("improvement-provider")
	apiKey, _ := cmd.Flags().GetString("api-key")
	llmURL, _ := cmd.Flags().GetString("llm-url")
	model, _ := cmd.Flags().GetString("model")

	if apiKey == "" {
		switch name {
		case "openai":
			apiKey = os.Getenv("OPENAI_API_KEY")
		case "anthropic":
			apiKey = os.Getenv("ANTHROPIC_API_KEY")
		}
	}

	cfg := types.ProviderConfig{
		Name:        name,
		APIKey:      apiKey,
		BaseURL:     llmURL,
		Model:       model,
		MaxTokens:   8192,
		Temperature: 0.3,
	}

	return llm.NewProvider(cfg)
}

func setupLocalProvider(cmd *cobra.Command, name string) (llm.Provider, error) {
	llmURL, _ := cmd.Flags().GetString("llm-url")
	cfg := types.ProviderConfig{
		Name:        name,
		BaseURL:     llmURL,
		MaxTokens:   8192,
		Temperature: 0.3,
	}
	return llm.NewProvider(cfg)
}

func findProjectRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found in parent directories")
		}
		dir = parent
	}
}

func resolvePath(root, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}

// Printing helpers

func printBanner() {
	banner := `
    ____          __                    ____                  __
   /  _/___  ____/ /____ _____ ____   / __ )___  ____  _____/ /_
   / // __ \/ __  / __  / __  / __ \ / __  / _ \/ __ \/ ___/ __ \
 _/ // / / / /_/ / /_/ / /_/ / /_/ // /_/ /  __/ / / / /__/ / / /
/___/_/ /_/\__,_/\__,_/\__, /\____//_____/\___/_/ /_/\___/_/ /_/
                      /____/
Iterative Detection Improvement Loop v%s
`
	fmt.Printf(banner, version)
	fmt.Println()
}

func printHeader(msg string) {
	fmt.Println()
	sep := strings.Repeat("=", 60)
	color.New(color.FgWhite, color.Bold).Println(sep)
	color.New(color.FgWhite, color.Bold).Printf("  %s\n", msg)
	color.New(color.FgWhite, color.Bold).Println(sep)
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

func printEvaluation(eval *benchmark.EvaluationResult) {
	fmt.Println()
	color.New(color.FgWhite, color.Bold).Println("  Evaluation Results:")
	fmt.Printf("    Recall:     %.1f%% (%d/%d)\n", eval.Recall*100, len(eval.TruePositives), eval.TotalGroundTrue)
	fmt.Printf("    Precision:  %.1f%%\n", eval.Precision*100)
	fmt.Printf("    F1 Score:   %.3f\n", eval.F1)
	fmt.Printf("    Avg Conf:   %.2f\n", eval.AvgConfidence)
	fmt.Printf("    Findings:   %d total, %d TP, %d FP\n",
		eval.TotalFindings, len(eval.TruePositives), len(eval.FalsePositives))
	fmt.Println()

	if len(eval.TruePositives) > 0 {
		color.Green("  Detected:")
		for _, tp := range eval.TruePositives {
			color.Green("    [x] %s — %s", tp.Vuln.ID, tp.Vuln.Name)
		}
	}
	if len(eval.FalseNegatives) > 0 {
		color.Red("  Missed:")
		for _, fn := range eval.FalseNegatives {
			color.Red("    [ ] %s — %s", fn.Vuln.ID, fn.Vuln.Name)
		}
	}
	fmt.Println()
}

func printGap(g benchmark.GapAnalysis) {
	color.Yellow("  Gap [%s] %s: %s", g.VulnID, g.Gap, g.Notes)
}

func printConvergence(iteration int, eval *benchmark.EvaluationResult) {
	printHeader("CONVERGENCE ACHIEVED")
	color.Green("  All %d vulnerabilities detected with high confidence!", eval.TotalGroundTrue)
	color.Green("  Zero false positives!")
	color.Green("  Converged after %d iterations", iteration)
}

func printFinalReport(tracker *benchmark.ConvergenceTracker) {
	printHeader("FINAL REPORT")
	fmt.Println()
	fmt.Printf("  %-5s  %-8s  %-8s  %-4s  %-4s  %-8s  %-10s\n",
		"Iter", "Recall", "Prec", "FP", "FN", "AvgConf", "Converged")
	fmt.Println("  " + strings.Repeat("-", 58))

	for _, rec := range tracker.History {
		converged := " "
		if rec.Converged {
			converged = "*"
		}
		fmt.Printf("  %-5d  %6.1f%%  %6.1f%%  %-4d  %-4d  %6.2f    %s\n",
			rec.Iteration, rec.Recall*100, rec.Precision*100,
			rec.FalsePositives, rec.FalseNegatives,
			rec.AvgConfidence, converged)
	}
	fmt.Println()

	// List all improvements applied
	fmt.Println("  Improvements applied:")
	for _, rec := range tracker.History {
		if len(rec.ImprovementsUsed) > 0 {
			fmt.Printf("    Iteration %d: %s\n", rec.Iteration, strings.Join(rec.ImprovementsUsed, ", "))
		}
	}
	fmt.Println()
}
