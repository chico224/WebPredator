package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Scanner configuration options
type ScannerConfig struct {
	Verbose       bool
	Threads       int
	OutputFile    string
	IncludeSubs   bool
	CheckActive   bool
	Timeout       int
	RateLimit     int
	UserAgent     string
	ExtendedScan  bool
	RemoveWild    bool
	UniqueOnly    bool
	JSONOutput    bool
	ConfigFile    string
	SourceFilter  string
}

// DomainScanner performs comprehensive domain discovery
type DomainScanner struct {
	Config      ScannerConfig
	HTTPClient  *http.Client
	RateLimiter <-chan time.Time
}

// NewDomainScanner creates a new scanner instance
func NewDomainScanner(cfg ScannerConfig) *DomainScanner {
	return &DomainScanner{
		Config: cfg,
		HTTPClient: &http.Client{
			Timeout: time.Duration(cfg.Timeout) * time.Second,
		},
	}
}

// Initialize sets up the scanner
func (ds *DomainScanner) Initialize() {
	if ds.Config.RateLimit > 0 {
		ds.RateLimiter = time.Tick(time.Second / time.Duration(ds.Config.RateLimit))
	}
}

// Run executes the scanning process
func (ds *DomainScanner) Run(domain string) error {
	if ds.Config.ConfigFile != "" {
		if err := ds.loadConfig(); err != nil {
			return fmt.Errorf("config loading failed: %w", err)
		}
	}

	results := make(chan string)
	var processing sync.WaitGroup

	sources := ds.getActiveSources()
	if ds.Config.Verbose {
		fmt.Fprintf(os.Stderr, "Using %d data sources\n", len(sources))
	}

	// Launch source workers
	for _, source := range sources {
		processing.Add(1)
		go func(source func(string) ([]string, error)) {
			defer processing.Done()
			ds.querySource(domain, source, results)
		}(source)
	}

	// Close results channel when all workers complete
	go func() {
		processing.Wait()
		close(results)
	}()

	// Prepare output destination
	output, err := ds.prepareOutput()
	if err != nil {
		return fmt.Errorf("output preparation failed: %w", err)
	}
	defer ds.finalizeOutput(output)

	// Process results
	uniqueDomains := make(map[string]bool)
	for result := range results {
		if ds.Config.UniqueOnly && uniqueDomains[result] {
			continue
		}
		uniqueDomains[result] = true

		if err := ds.writeResult(output, result); err != nil {
			return fmt.Errorf("result writing failed: %w", err)
		}
	}

	// Check active domains if configured
	if ds.Config.CheckActive {
		if err := ds.checkActiveDomains(uniqueDomains, output); err != nil {
			return fmt.Errorf("active check failed: %w", err)
		}
	}

	return nil
}

// querySource handles communication with a single data source
func (ds *DomainScanner) querySource(domain string, source func(string) ([]string, error), results chan<- string) {
	if ds.Config.RateLimit > 0 {
		<-ds.RateLimiter
	}

	subdomains, err := source(domain)
	if err != nil && ds.Config.Verbose {
		fmt.Fprintf(os.Stderr, "Source error: %v\n", err)
		return
	}

	for _, sub := range subdomains {
		if ds.Config.RemoveWild && isWildcardDomain(sub) {
			continue
		}

		if !ds.Config.IncludeSubs && isSubdomain(sub) {
			continue
		}

		results <- sub
	}
}

// prepareOutput sets up the output destination
func (ds *DomainScanner) prepareOutput() (io.Writer, error) {
	if ds.Config.OutputFile == "" {
		return os.Stdout, nil
	}

	file, err := os.Create(ds.Config.OutputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	return file, nil
}

// finalizeOutput handles output cleanup
func (ds *DomainScanner) finalizeOutput(output io.Writer) {
	if file, ok := output.(*os.File); ok && file != os.Stdout {
		file.Close()
	}
}

// writeResult formats and writes a result
func (ds *DomainScanner) writeResult(output io.Writer, result string) error {
	if ds.Config.JSONOutput {
		_, err := fmt.Fprintf(output, "{\"domain\":\"%s\"}\n", result)
		return err
	}
	_, err := fmt.Fprintln(output, result)
	return err
}

// checkActiveDomains verifies which domains are responsive
func (ds *DomainScanner) checkActiveDomains(domains map[string]bool, output io.Writer) error {
	activeChecker := NewActiveChecker(ds.Config.Timeout, ds.Config.Threads, ds.Config.UserAgent)

	urls := make([]string, 0, len(domains)*2)
	for domain := range domains {
		urls = append(urls, "http://"+domain)
		urls = append(urls, "https://"+domain)
	}

	activeUrls := activeChecker.Check(urls)
	for url := range activeUrls {
		if err := ds.writeActiveResult(output, url); err != nil {
			return err
		}
	}

	return nil
}

// writeActiveResult formats and writes an active domain result
func (ds *DomainScanner) writeActiveResult(output io.Writer, url string) error {
	if ds.Config.JSONOutput {
		_, err := fmt.Fprintf(output, "{\"url\":\"%s\",\"active\":true}\n", url)
		return err
	}
	_, err := fmt.Fprintln(output, url)
	return err
}

// Helper functions
func isSubdomain(domain string) bool {
	return strings.Count(domain, ".") > 1
}

func isWildcardDomain(domain string) bool {
	return strings.HasPrefix(domain, "*.")
}

func (ds *DomainScanner) loadConfig() error {
	// Implementation for config loading
	return nil
}

func (ds *DomainScanner) getActiveSources() []func(string) ([]string, error) {
	// Implementation for source selection
	return []func(string) ([]string, error){}
}

// ActiveChecker verifies responsive domains
type ActiveChecker struct {
	Client      *http.Client
	Concurrency int
	UserAgent   string
}

// NewActiveChecker creates a new instance
func NewActiveChecker(timeout, concurrency int, userAgent string) *ActiveChecker {
	return &ActiveChecker{
		Client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		Concurrency: concurrency,
		UserAgent:   userAgent,
	}
}

// Check verifies which URLs are responsive
func (ac *ActiveChecker) Check(urls []string) <-chan string {
	results := make(chan string)
	var wg sync.WaitGroup
	workChan := make(chan string, ac.Concurrency)

	// Start worker pool
	for i := 0; i < ac.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range workChan {
				if ac.isActive(url) {
					results <- url
				}
			}
		}()
	}

	// Feed URLs to workers
	go func() {
		for _, url := range urls {
			workChan <- url
		}
		close(workChan)
		wg.Wait()
		close(results)
	}()

	return results
}

// isActive checks if a single URL is responsive
func (ac *ActiveChecker) isActive(url string) bool {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", ac.UserAgent)

	resp, err := ac.Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode < 400
}

func main() {
	cfg := ScannerConfig{
		Verbose:      *flag.Bool("v", false, "Show detailed output"),
		Threads:      *flag.Int("t", 20, "Concurrent worker count"),
		OutputFile:   *flag.String("o", "", "Results output file"),
		IncludeSubs:  *flag.Bool("subs", false, "Include subdomains"),
		CheckActive:  *flag.Bool("active", false, "Verify active domains"),
		Timeout:      *flag.Int("timeout", 10, "Request timeout in seconds"),
		RateLimit:    *flag.Int("rate", 0, "Requests per second limit"),
		UserAgent:    *flag.String("ua", "DomainScanner/1.0", "HTTP User-Agent"),
		ExtendedScan: *flag.Bool("extended", false, "Use extended sources"),
		RemoveWild:   *flag.Bool("nowild", false, "Exclude wildcard domains"),
		UniqueOnly:   *flag.Bool("unique", true, "Output only unique domains"),
		JSONOutput:   *flag.Bool("json", false, "JSON format output"),
		ConfigFile:   *flag.String("config", "", "Configuration file"),
		SourceFilter: *flag.String("source", "", "Specific source to use"),
	}

	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	scanner := NewDomainScanner(cfg)
	scanner.Initialize()

	if err := scanner.Run(flag.Arg(0)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}