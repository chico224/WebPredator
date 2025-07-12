/*
 * DomainHunter Pro - Advanced Subdomain Discovery Tool
 * Next-generation subdomain enumeration with enhanced capabilities
 * 
 * Commercial License (see LICENSE.md)
 */

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"
	"golang.org/x/sync/semaphore"

	// Enhanced modules
	"github.com/projectdiscovery/chaos-client/pkg/chaos"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/notify/pkg/notify"
	"github.com/projectdiscovery/shuffledns/pkg/shuffledns"
	"gopkg.in/yaml.v2"
)

// Config contains the enhanced configuration
type Config struct {
	API struct {
		Chaos          string `yaml:"chaos"`
		SecurityTrails string `yaml:"securitytrails"`
		Shodan         string `yaml:"shodan"`
		VirusTotal     string `yaml:"virustotal"`
	} `yaml:"api"`

	Cloud struct {
		AWS   bool `yaml:"aws"`
		Azure bool `yaml:"azure"`
		GCP   bool `yaml:"gcp"`
	} `yaml:"cloud"`

	Engine struct {
		Threads        int  `yaml:"threads"`
		RateLimit      int  `yaml:"rate_limit"`
		Monitor        bool `yaml:"monitor"`
		Historical     bool `yaml:"historical"`
		Permutations   bool `yaml:"permutations"`
		CertTransparency bool `yaml:"cert_transparency"`
	} `yaml:"engine"`

	Notifications struct {
		Slack    string `yaml:"slack"`
		Discord  string `yaml:"discord"`
		Telegram string `yaml:"telegram"`
	} `yaml:"notifications"`
}

// DomainHunter represents the main scanner
type DomainHunter struct {
	*runner.Runner
	config      *Config
	chaos       *chaos.Client
	dns         *dnsx.DNSX
	http        *httpx.Client
	notifier    *notify.Client
	shuffleDNS  *shuffledns.Client
	rateLimiter *ratelimit.Limiter
}

func main() {
	var (
		domains      = flag.String("d", "", "Target domains (comma-separated)")
		domainFile   = flag.String("df", "", "File containing domains")
		output       = flag.String("o", "", "Output file")
		configFile   = flag.String("c", "domainhunter.yaml", "Configuration file")
		threads      = flag.Int("t", 10, "Concurrent threads")
		rateLimit    = flag.Int("rl", 5, "Requests per second")
		verbose      = flag.Bool("v", false, "Verbose output")
		jsonOutput   = flag.Bool("json", false, "JSON output format")
		monitor      = flag.Bool("monitor", false, "Continuous monitoring")
		cloudScan    = flag.Bool("cloud", false, "Cloud provider scan")
		activeScan   = flag.Bool("active", false, "Active verification")
		historical   = flag.Bool("hist", false, "Historical data")
		permutations = flag.Bool("perm", false, "Subdomain permutations")
		notify       = flag.String("notify", "", "Notification service")
	)

	flag.Parse()

	// Load enhanced configuration
	cfg, err := loadConfig(*configFile)
	if err != nil {
		gologger.Fatal().Msgf("Config error: %s\n", err)
	}

	// Initialize DomainHunter
	hunter, err := NewDomainHunter(cfg, *threads, *rateLimit, *monitor, *cloudScan, *activeScan)
	if err != nil {
		gologger.Fatal().Msgf("Initialization failed: %s\n", err)
	}

	// Process input domains
	var targets []string
	if *domains != "" {
		targets = strings.Split(*domains, ",")
	} else if *domainFile != "" {
		targets, err = readTargets(*domainFile)
		if err != nil {
			gologger.Fatal().Msgf("Target error: %s\n", err)
		}
	} else {
		gologger.Fatal().Msg("No targets specified")
	}

	// Execute scan
	results, err := hunter.Scan(targets, *historical, *permutations)
	if err != nil {
		gologger.Fatal().Msgf("Scan failed: %s\n", err)
	}

	// Handle output
	if *output != "" {
		err = writeOutput(*output, results, *jsonOutput)
		if err != nil {
			gologger.Fatal().Msgf("Output error: %s\n", err)
		}
	} else {
		for _, r := range results {
			fmt.Println(r)
		}
	}

	// Send notifications
	if *notify != "" {
		err = hunter.Notify(*notify, results)
		if err != nil {
			gologger.Error().Msgf("Notification failed: %s\n", err)
		}
	}

	// Start monitoring if enabled
	if *monitor {
		hunter.Monitor(targets, 24*time.Hour)
	}
}

func loadConfig(file string) (*Config, error) {
	cfg := &Config{}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

func NewDomainHunter(cfg *Config, threads, rate int, monitor, cloud, active bool) (*DomainHunter, error) {
	// Initialize base runner
	base, err := runner.NewRunner(&runner.Options{
		Threads:            threads,
		Timeout:            30,
		MaxEnumerationTime: 10,
	})
	if err != nil {
		return nil, err
	}

	// Set up enhanced modules
	chaosClient := chaos.New(cfg.API.Chaos)
	dnsClient, err := dnsx.New(dnsx.DefaultOptions)
	if err != nil {
		return nil, err
	}

	httpClient, err := httpx.New(httpx.DefaultOptions)
	if err != nil {
		return nil, err
	}

	notifyClient := notify.New()
	shuffleClient := shuffledns.New(shuffledns.DefaultOptions)
	limiter := ratelimit.New(rate)

	return &DomainHunter{
		Runner:      base,
		config:      cfg,
		chaos:       chaosClient,
		dns:         dnsClient,
		http:        httpClient,
		notifier:    notifyClient,
		shuffleDNS:  shuffleClient,
		rateLimiter: limiter,
	}, nil
}

func (h *DomainHunter) Scan(domains []string, historical, permutations bool) ([]string, error) {
	var results []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := semaphore.NewWeighted(int64(h.Runner.Options.Threads))
	ctx := context.Background()

	for _, domain := range domains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()

			if err := sem.Acquire(ctx, 1); err != nil {
				gologger.Error().Msgf("Semaphore error: %s\n", err)
				return
			}
			defer sem.Release(1)

			h.rateLimiter.Take()

			gologger.Info().Msgf("Scanning %s\n", d)

			// Passive discovery
			passiveResults, err := h.Runner.EnumerateSubdomains(d, passive.DefaultSources)
			if err != nil {
				gologger.Error().Msgf("Enumeration error: %s\n", err)
				return
			}

			// Enhanced discovery
			enhancedResults := h.enhancedDiscovery(d, historical, permutations)

			// Combine results
			combined := mergeResults(passiveResults, enhancedResults)

			// Active verification if enabled
			if h.config.Engine.Monitor || h.config.Engine.Historical {
				verified := h.verifySubdomains(combined)
				mu.Lock()
				results = append(results, verified...)
				mu.Unlock()
			} else {
				mu.Lock()
				results = append(results, combined...)
				mu.Unlock()
			}
		}(domain)
	}

	wg.Wait()
	return deduplicate(results), nil
}

func (h *DomainHunter) enhancedDiscovery(domain string, historical, permutations bool) []string {
	var results []string

	// Chaos API
	if h.config.API.Chaos != "" {
		chaosResults, err := h.chaos.GetSubdomains(domain)
		if err != nil {
			gologger.Error().Msgf("Chaos error: %s\n", err)
		} else {
			results = append(results, chaosResults...)
		}
	}

	// Historical data
	if historical {
		historyResults := h.historicalData(domain)
		results = append(results, historyResults...)
	}

	// Permutations
	if permutations {
		permResults := h.generatePermutations(domain)
		results = append(results, permResults...)
	}

	// Cloud services
	if h.config.Cloud.AWS || h.config.Cloud.Azure || h.config.Cloud.GCP {
		cloudResults := h.cloudDiscovery(domain)
		results = append(results, cloudResults...)
	}

	// Certificate Transparency
	if h.config.Engine.CertTransparency {
		ctResults := h.certificateSearch(domain)
		results = append(results, ctResults...)
	}

	return results
}

func (h *DomainHunter) historicalData(domain string) []string {
	var results []string

	if h.config.API.SecurityTrails != "" {
		// SecurityTrails implementation
	}

	if h.config.API.Shodan != "" {
		// Shodan implementation
	}

	if h.config.API.VirusTotal != "" {
		// VirusTotal implementation
	}

	return results
}

func (h *DomainHunter) generatePermutations(domain string) []string {
	var results []string

	words := []string{"dev", "test", "stage", "prod", "api", "admin"}

	for _, word := range words {
		results = append(results, fmt.Sprintf("%s.%s", word, domain))
	}

	return h.verifySubdomains(results)
}

func (h *DomainHunter) cloudDiscovery(domain string) []string {
	var results []string

	if h.config.Cloud.AWS {
		results = append(results, fmt.Sprintf("s3.%s", domain))
		results = append(results, fmt.Sprintf("ec2.%s", domain))
	}

	if h.config.Cloud.Azure {
		results = append(results, fmt.Sprintf("azure.%s", domain))
	}

	if h.config.Cloud.GCP {
		results = append(results, fmt.Sprintf("gcp.%s", domain))
	}

	return results
}

func (h *DomainHunter) certificateSearch(domain string) []string {
	var results []string
	// Certificate transparency implementation
	return results
}

func (h *DomainHunter) verifySubdomains(subdomains []string) []string {
	var verified []string

	for _, sub := range subdomains {
		_, err := h.dns.Query(sub)
		if err != nil {
			continue
		}

		if h.config.Engine.Monitor {
			resp, err := h.http.Get("http://" + sub)
			if err == nil && resp.StatusCode < 500 {
				verified = append(verified, sub)
			}
		} else {
			verified = append(verified, sub)
		}
	}

	return verified
}

func (h *DomainHunter) Monitor(domains []string, interval time.Duration) {
	gologger.Info().Msgf("Starting monitoring with interval %v\n", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	previous := make(map[string][]string)

	for range ticker.C {
		for _, domain := range domains {
			current, err := h.Scan([]string{domain}, h.config.Engine.Historical, h.config.Engine.Permutations)
			if err != nil {
				gologger.Error().Msgf("Monitoring error: %s\n", err)
				continue
			}

			newSubs := findNewSubdomains(current, previous[domain])
			if len(newSubs) > 0 {
				gologger.Warning().Msgf("New subdomains found for %s:\n", domain)
				for _, sub := range newSubs {
					gologger.Warning().Msgf("- %s\n", sub)
				}

				if h.config.Notifications.Slack != "" {
					h.notifier.Slack(h.config.Notifications.Slack, 
						fmt.Sprintf("New subdomains for %s: %v", domain, newSubs))
				}

				previous[domain] = current
			}
		}
	}
}

func (h *DomainHunter) Notify(service string, results []string) error {
	msg := fmt.Sprintf("Scan completed. Found %d subdomains.", len(results))

	switch service {
	case "slack":
		return h.notifier.Slack(h.config.Notifications.Slack, msg)
	case "discord":
		return h.notifier.Discord(h.config.Notifications.Discord, msg)
	case "telegram":
		return h.notifier.Telegram(h.config.Notifications.Telegram, msg)
	default:
		return fmt.Errorf("Unknown service: %s", service)
	}
}

// Utility functions

func readTargets(file string) ([]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func writeOutput(file string, results []string, jsonFormat bool) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	if jsonFormat {
		return json.NewEncoder(f).Encode(results)
	}

	w := bufio.NewWriter(f)
	for _, r := range results {
		_, err := w.WriteString(r + "\n")
		if err != nil {
			return err
		}
	}
	return w.Flush()
}

func deduplicate(slice []string) []string {
	keys := make(map[string]bool)
	var unique []string
	for _, v := range slice {
		if !keys[v] {
			keys[v] = true
			unique = append(unique, v)
		}
	}
	return unique
}

func mergeResults(a, b []string) []string {
	set := make(map[string]bool)
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		set[v] = true
	}

	var merged []string
	for k := range set {
		merged = append(merged, k)
	}
	return merged
}

func findNewSubdomains(current, previous []string) []string {
	set := make(map[string]bool)
	for _, v := range previous {
		set[v] = true
	}

	var new []string
	for _, v := range current {
		if !set[v] {
			new = append(new, v)
		}
	}
	return new
}