// main.go is the entry point of the osintmaster CLI tool
package main

import (
	"encoding/json"
	"flag" // standard library for parsing command-line flags
	"fmt"
	"os"
	"path/filepath"

	// import our internal packages
	"osint-master/internal/domain"
	"osint-master/internal/ip"
	"osint-master/internal/username"
)

// saveOutput writes any data structure to a JSON file in the output/ directory
func saveOutput(data any, filename string) error {
	// create output directory if it doesn't exist
	if err := os.MkdirAll("output", 0755); err != nil {
		return err
	}

	path := filepath.Join("output", filename)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// write formatted JSON (SetIndent makes it human-readable)
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return err
	}

	fmt.Printf("\nData saved in %s\n", path)
	return nil
}

func main() {
	// define command-line flags
	// flag.String(name, default_value, description)
	ipFlag := flag.String("i", "", "IP address to look up")
	usernameFlag := flag.String("u", "", "Username to search")
	domainFlag := flag.String("d", "", "Domain to enumerate")
	outputFlag := flag.String("o", "", "Output filename")

	// customize the help message shown with --help
	flag.Usage = func() {
		fmt.Println(`
Welcome to OSINT-Master

OPTIONS:
  -i  "IP Address"   Search information by IP address
  -u  "Username"     Search information by username
  -d  "Domain"       Enumerate subdomains and check for takeover risks
  -o  "FileName"     File name to save output
		`)
	}

	// parse the flags from os.Args (command line input)
	flag.Parse()

	// check which flag was provided and run the correct module
	switch {
	case *ipFlag != "":
		fmt.Printf("\n[*] Looking up IP: %s\n", *ipFlag)

		info, err := ip.Lookup(*ipFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1) // exit with error code 1
		}
		info.Print()

		// save to file only if -o flag was provided
		if *outputFlag != "" {
			saveOutput(info, *outputFlag)
		}

	case *usernameFlag != "":
		fmt.Printf("\n[*] Searching username: %s\n", *usernameFlag)

		results := username.Lookup(*usernameFlag)
		username.PrintResults(results)

		if *outputFlag != "" {
			saveOutput(results, *outputFlag)
		}

	case *domainFlag != "":
		fmt.Printf("\n[*] Enumerating domain: %s\n", *domainFlag)

		// get list of subdomains from crt.sh
		subs, err := domain.GetSubdomains(*domainFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  Subdomains found: %d\n\n", len(subs))

		// for each subdomain collect IP, SSL, and takeover risk
		var results []domain.SubdomainInfo
		for _, sub := range subs {
			info := domain.SubdomainInfo{
				Name:         sub,
				IP:           domain.ResolveIP(sub),
				SSLExpiry:    domain.GetSSLExpiry(sub),
				TakeoverRisk: domain.CheckTakeoverRisk(sub),
			}
			results = append(results, info)
		}

		domain.PrintResults(results)

		if *outputFlag != "" {
			// wrap results in a map to include the main domain in the output
			saveOutput(map[string]any{
				"domain":     *domainFlag,
				"subdomains": results,
			}, *outputFlag)
		}

	default:
		// no valid flag provided — show help
		flag.Usage()
	}
}
