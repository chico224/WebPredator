package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/rs/xid"
)

// ScannerConfig contains enhanced configuration
type ScannerConfig struct {
	Targets         []string      `json:"targets"`
	TargetsFile     string        `json:"targets_file"`
	WAFBypass       bool          `json:"waf_bypass"`
	ContinuousMode  bool          `json:"continuous_mode"`
	SlackWebhook    string        `json:"slack_webhook"`
	DiscordWebhook  string        `json:"discord_webhook"`
	DashboardPort   int           `json:"dashboard_port"`
	CVEUpdate       bool          `json:"cve_update"`
	AutoTechDetect  bool          `json:"tech_detect"`
	ReportFormat    string        `json:"report_format"`
	MonitoringDelay time.Duration `json:"monitoring_delay"`
	Threads         int           `json:"threads"`
	OutputFile      string        `json:"output_file"`
	Timeout         time.Duration `json:"timeout"`
	RateLimit       int           `json:"rate_limit"`
	Proxy           string        `json:"proxy"`
	InsecureTLS     bool          `json:"insecure_tls"`
	Syslog          bool          `json:"syslog"`
	ConfigPath      string        `json:"config_path"`
	SelfUpdate      bool          `json:"self_update"`
	InstallService  bool          `json:"install_service"`
	UninstallService bool         `json:"uninstall_service"`
}

// ScanResult represents a vulnerability finding
type ScanResult struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Finding  string `json:"finding"`
	Severity string `json:"severity"`
}

// ScannerEngine handles the core scanning functionality
type ScannerEngine struct {
	config       *ScannerConfig
	httpClient   *http.Client
	cveDB        map[string]string
	shutdownChan chan struct{}
	rateLimiter  <-chan time.Time
	results      []ScanResult
	mu           sync.Mutex
}

func main() {
	defer globalCrashHandler()

	config := parseFlags()
	engine, err := NewScannerEngine(config)
	if err != nil {
		fmt.Printf("Failed to initialize scanner: %s\n", err)
		os.Exit(1)
	}

	if config.CVEUpdate {
		if err := engine.UpdateCVEDatabase(); err != nil {
			fmt.Printf("CVE update failed: %s\n", err)
		}
	}

	if config.ContinuousMode {
		go engine.StartContinuousMonitoring()
	}

	if config.DashboardPort > 0 {
		go engine.StartDashboard()
	}

	if err := engine.RunScan(); err != nil {
		fmt.Printf("Scan failed: %s\n", err)
		os.Exit(1)
	}
}

func parseFlags() *ScannerConfig {
	config := &ScannerConfig{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("WebPredator - Advanced Vulnerability Scanner")

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&config.Targets, "target", "u", []string{}, "Targets to scan"),
		flagSet.StringVarP(&config.TargetsFile, "list", "l", "", "File containing targets"),
	)

	flagSet.CreateGroup("enhanced", "Enhanced Features",
		flagSet.BoolVar(&config.WAFBypass, "waf-bypass", false, "Enable WAF bypass techniques"),
		flagSet.BoolVar(&config.ContinuousMode, "continuous", false, "Continuous monitoring mode"),
		flagSet.StringVar(&config.SlackWebhook, "slack", "", "Slack webhook URL"),
		flagSet.StringVar(&config.DiscordWebhook, "discord", "", "Discord webhook URL"),
		flagSet.IntVar(&config.DashboardPort, "dashboard", 0, "Web dashboard port"),
		flagSet.BoolVar(&config.CVEUpdate, "update-cve", false, "Update CVE database before scan"),
		flagSet.BoolVar(&config.AutoTechDetect, "tech-detect", false, "Enable technology detection"),
		flagSet.StringVar(&config.ReportFormat, "report-format", "json", "Report format (json,html,markdown)"),
		flagSet.DurationVar(&config.MonitoringDelay, "monitor-delay", 5*time.Minute, "Delay between scans"),
		flagSet.IntVar(&config.Threads, "threads", 10, "Number of concurrent threads"),
		flagSet.StringVar(&config.OutputFile, "output", "", "Write scan results to specified file"),
		flagSet.DurationVar(&config.Timeout, "timeout", 10*time.Second, "HTTP timeout per request"),
		flagSet.IntVar(&config.RateLimit, "rate-limit", 0, "Maximum requests per second (0 = unlimited)"),
		flagSet.StringVar(&config.Proxy, "proxy", "", "HTTP proxy URL (e.g. http://127.0.0.1:8080)"),
		flagSet.BoolVar(&config.InsecureTLS, "insecure", false, "Skip TLS certificate verification"),
		flagSet.BoolVar(&config.Syslog, "syslog", false, "Write critical logs to syslog / EventLog"),
		flagSet.StringVar(&config.ConfigPath, "config", "", "Load configuration from file (json|yaml)"),
		flagSet.BoolVar(&config.SelfUpdate, "self-update", false, "Check and apply latest update"),
		flagSet.BoolVar(&config.InstallService, "install-service", false, "Install as system service/daemon"),
		flagSet.BoolVar(&config.UninstallService, "uninstall-service", false, "Uninstall service/daemon"),
	)

	if err := flagSet.Parse(); err != nil {
		fmt.Printf("Failed to parse flags: %s\n", err)
		os.Exit(1)
	}

	// Load external config if provided
	if config.ConfigPath != "" {
		loadExternalConfig(config)
	}

	// Auto threads if zero
	if config.Threads == 0 {
		config.Threads = runtime.NumCPU() * 2
	}
		fmt.Printf("Failed to parse flags: %s\n", err)
		os.Exit(1)
	}

	return config
}

func NewScannerEngine(config *ScannerConfig) (*ScannerEngine, error) {
	transport := &http.Transport{
		MaxIdleConns:        config.Threads,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
	}

	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	if config.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}
		Timeout: config.Timeout,
		Transport: &http.Transport{
			MaxIdleConns:        config.Threads,
			IdleConnTimeout:    30 * time.Second,
			DisableCompression: false,
		},
	}

	if config.WAFBypass {
		// Enhanced evasion techniques
		client.Transport = &evasiveTransport{
			RoundTripper: http.DefaultTransport,
		}
	}

	var rl <-chan time.Time
	if config.RateLimit > 0 {
		rl = time.Tick(time.Second / time.Duration(config.RateLimit))
	}

	checksumSelf()

	return &ScannerEngine{
		config:       config,
		httpClient:   client,
		cveDB:        make(map[string]string),
		shutdownChan: make(chan struct{}),
		rateLimiter:  rl,
		results:      make([]ScanResult, 0),
	}, nil
}

type evasiveTransport struct {
	http.RoundTripper
}

func (t *evasiveTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Add WAF evasion headers
	req.Header.Set("X-Forwarded-For", generateRandomIP())
	req.Header.Set("User-Agent", randomUserAgent())
	return t.RoundTripper.RoundTrip(req)
}

func (e *ScannerEngine) RunScan() error {
	// Load targets
	targets, err := e.loadTargets()
	if err != nil {
		return err
	}

	// Process scanning
	results := make(chan ScanResult)
	var wg sync.WaitGroup

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			e.scanTarget(t, results)
		}(target)
	}

	// Handle results
	go func() {
		for result := range results {
			e.processResult(result)
		}
	}()

	wg.Wait()
	close(results)

	if e.config.OutputFile != "" {
		if err := e.writeResultsToFile(); err != nil {
			fmt.Printf("Failed to write results: %s\n", err)
		}
	}
	return nil
}

func (e *ScannerEngine) scanTarget(target string, results chan<- ScanResult) {
	// Implement actual scanning logic here
	if e.rateLimiter != nil {
		<-e.rateLimiter
	}

	resp, err := e.httpClient.Get(target)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Example detection
	if resp.StatusCode == 200 {
		results <- ScanResult{
			ID:       xid.New().String(),
			Host:     target,
			Finding:  "Potential vulnerability detected",
			Severity: "medium",
		}
	}
}

func (e *ScannerEngine) processResult(result ScanResult) {
	e.mu.Lock()
	defer e.mu.Unlock()

	color := ""
	reset := "\033[0m"
	switch strings.ToLower(result.Severity) {
	case "high":
		color = "\033[31m" // red
	case "medium":
		color = "\033[33m" // yellow
	case "low":
		color = "\033[32m" // green
	default:
		color = ""
	}
	fmt.Printf("%s[%s]%s %s - %s\n", color, strings.ToUpper(result.Severity), reset, result.Host, result.Finding)
	e.results = append(e.results, result)

	// Generate reports
	switch e.config.ReportFormat {
	case "html":
		e.generateHTMLReport(result)
	case "markdown":
		e.generateMarkdownReport(result)
	default:
		e.generateJSONReport(result)
	}

	// Send notifications
	if e.config.SlackWebhook != "" {
		go e.sendToSlack(result)
	}
	if e.config.DiscordWebhook != "" {
		go e.sendToDiscord(result)
	}
}

// Additional helper methods would be implemented here...

func (e *ScannerEngine) StartContinuousMonitoring() {
	ticker := time.NewTicker(e.config.MonitoringDelay)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fmt.Println("[*] Running periodic scan...")
			_ = e.RunScan()
		case <-e.shutdownChan:
			return
		}
	}
}

func (e *ScannerEngine) StartDashboard() {
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", e.config.DashboardPort),
		Handler: e.createDashboardHandler(),
	}

	go func() {
		fmt.Printf("[*] Dashboard started on http://localhost:%d\n", e.config.DashboardPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Dashboard error: %s\n", err)
		}
	}()

	<-e.shutdownChan
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

// writeResultsToFile saves accumulated results to the specified output file.
func (e *ScannerEngine) writeResultsToFile() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	file, err := os.Create(e.config.OutputFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(e.results)
}

// loadExternalConfig merges values from a JSON/YAML file into existing config (fields already set via flags are kept).
func loadExternalConfig(cfg *ScannerConfig) {
	data, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		fmt.Printf("[!] Failed to read config file: %s\n", err)
		return
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		// try YAML
		if yamlErr := yaml.Unmarshal(data, &m); yamlErr != nil {
			fmt.Printf("[!] Invalid config format: %s\n", err)
			return
		}
	}
	override := func(key string, setter func(interface{})) {
		if v, ok := m[key]; ok {
			setter(v)
		}
	}
	override("threads", func(v interface{}) { if cfg.Threads == 10 { cfg.Threads = int(v.(float64)) } })
	// ... add other overrides as needed
}

// globalCrashHandler writes panic info to OS-specific location.
func globalCrashHandler() {
	if r := recover(); r != nil {
		stack := make([]byte, 1<<16)
		_ = runtime.Stack(stack, true)
		dir := crashDir()
		os.MkdirAll(dir, 0700)
		file := filepath.Join(dir, fmt.Sprintf("crash-%d.log", time.Now().Unix()))
		_ = os.WriteFile(file, append([]byte(fmt.Sprint(r, "\n")), stack...), 0600)
		fmt.Printf("[!] Crash captured: %s\n", file)
	}
}

func crashDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "MonTool")
	}
	return filepath.Join(os.Getenv("HOME"), ".montool")
}

// checksumSelf computes SHA256 of running binary for integrity check.
func checksumSelf() {
	exe, err := os.Executable()
	if err != nil { return }
	f, err := os.Open(exe)
	if err != nil { return }
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err == nil {
		fmt.Printf("[*] Binary SHA256: %x\n", h.Sum(nil))
	}
}

// Implement remaining methods...