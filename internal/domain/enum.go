// Package domain handles subdomain enumeration and takeover risk detection
package domain

import (
	"crypto/tls" // for SSL certificate inspection
	"fmt"
	"io"
	"net" // for DNS lookups and TCP connections
	"net/http"
	"strings"
	"time"
)

// SubdomainInfo holds all data collected for one subdomain
type SubdomainInfo struct {
	Name         string `json:"subdomain"`
	IP           string `json:"ip"`
	SSLExpiry    string `json:"ssl_expiry"`
	TakeoverRisk string `json:"takeover_risk,omitempty"` // omitempty = skip if empty in JSON
}

// CrtShEntry represents one entry from crt.sh API response
type CrtShEntry struct {
	NameValue string `json:"name_value"` // contains subdomain names
}

// GetSubdomains fetches subdomains using Certificate Transparency Logs via crt.sh
// crt.sh is a public database of SSL certificates — every cert issued for a domain is logged there
// GetSubdomains fetches subdomains using HackerTarget API
// HackerTarget is more reliable than crt.sh for network-restricted environments
func GetSubdomains(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)

	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackertarget request failed: %w", err)
	}
	defer resp.Body.Close()

	// HackerTarget returns plain text: "subdomain,ip" per line
	// Example: www.example.com,93.184.216.34
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// check if API returned an error message
	bodyStr := string(body)
	if strings.HasPrefix(bodyStr, "error") || strings.HasPrefix(bodyStr, "API") {
		return nil, fmt.Errorf("hackertarget API error: %s", bodyStr)
	}

	// parse each line and extract subdomain name
	seen := make(map[string]bool)
	var subdomains []string

	for _, line := range strings.Split(bodyStr, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// each line is "subdomain,ip" — take only the subdomain part
		parts := strings.Split(line, ",")
		if len(parts) >= 1 {
			name := parts[0]
			if strings.Contains(name, domain) && !seen[name] {
				seen[name] = true
				subdomains = append(subdomains, name)
			}
		}
	}

	return subdomains, nil
}

// ResolveIP performs a DNS lookup to get the IP address of a hostname
func ResolveIP(hostname string) string {
	addrs, err := net.LookupHost(hostname)
	if err != nil || len(addrs) == 0 {
		return "Unresolvable" // DNS lookup failed — domain may be dangling
	}
	return addrs[0] // return the first IP address found
}

// GetSSLExpiry connects to port 443 and reads the SSL certificate expiry date
func GetSSLExpiry(hostname string) string {
	// dial with a short timeout so we don't hang on unreachable hosts
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp",
		hostname+":443",
		&tls.Config{InsecureSkipVerify: false}, // verify SSL cert is valid
	)
	if err != nil {
		return "Not found"
	}
	defer conn.Close()

	// get the certificate chain and read expiry from the first cert
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "Not found"
	}
	// format date as YYYY-MM-DD
	return certs[0].NotAfter.Format("2006-01-02")
}

// CheckTakeoverRisk detects potential subdomain takeover vulnerabilities
// A takeover risk exists when a subdomain has a CNAME pointing to an external
// service (like AWS S3, Heroku, GitHub Pages) that no longer exists
func CheckTakeoverRisk(subdomain string) string {
	ip := ResolveIP(subdomain)

	if ip == "Unresolvable" {
		// check if there is a CNAME record pointing somewhere
		cname, err := net.LookupCNAME(subdomain)
		if err == nil && cname != subdomain+"." {
			// CNAME exists but IP doesn't resolve = classic takeover risk
			return fmt.Sprintf(
				"CNAME points to %s but IP is unresolvable — potential takeover risk",
				cname,
			)
		}
		return "IP unresolvable — possible dangling DNS record"
	}
	return "" // no risk detected
}

// PrintResults displays subdomain scan results in the terminal
func PrintResults(subdomains []SubdomainInfo) {
	for _, s := range subdomains {
		if s.TakeoverRisk != "" {
			// highlight risky subdomains with [!]
			fmt.Printf("  [!] RISK: %s\n      %s\n", s.Name, s.TakeoverRisk)
		} else {
			fmt.Printf("  - %s (IP: %s, SSL: %s)\n", s.Name, s.IP, s.SSLExpiry)
		}
	}
}
