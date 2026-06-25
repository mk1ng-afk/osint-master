// Package domain handles subdomain enumeration and takeover risk detection
package domain

import (
	"crypto/tls" // for SSL certificate inspection
	"encoding/json"
	"fmt"
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
func GetSubdomains(domain string) ([]string, error) {
	// %25 is URL-encoded % — we search for wildcard *.domain.com
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	// parse the JSON array from crt.sh
	var entries []CrtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to parse crt.sh response: %w", err)
	}

	// use a map to deduplicate subdomains (crt.sh returns many duplicates)
	seen := make(map[string]bool)
	var subdomains []string

	for _, e := range entries {
		// name_value can contain multiple subdomains separated by newlines
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(name)
			// skip wildcards (*.example.com) and unrelated domains
			if strings.Contains(name, domain) && !strings.HasPrefix(name, "*") {
				if !seen[name] {
					seen[name] = true
					subdomains = append(subdomains, name)
				}
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
