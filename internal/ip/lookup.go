// Package ip handles IP address lookups using ip-api.com (free, no key needed)
package ip

import (
	"encoding/json" // for parsing JSON responses
	"fmt"
	"net/http" // for making HTTP requests
)

// IPInfo stores all data we get back from the API
type IPInfo struct {
	IP      string `json:"query"`   // the IP address
	ISP     string `json:"isp"`     // internet service provider
	City    string `json:"city"`    // city location
	Country string `json:"country"` // country location
	AS      string `json:"as"`      // autonomous system number (ASN)
	Status  string `json:"status"`  // "success" or "fail"
}

// Lookup sends a GET request to ip-api.com and returns IP information
func Lookup(ipAddr string) (*IPInfo, error) {
	// build the request URL with the target IP
	url := fmt.Sprintf("http://ip-api.com/json/%s", ipAddr)

	// send HTTP GET request
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() // always close the response body when done

	// decode JSON response into our IPInfo struct
	var info IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// check if the API returned a valid result
	if info.Status != "success" {
		return nil, fmt.Errorf("invalid IP address: %s", ipAddr)
	}

	return &info, nil
}

// Print displays the IP info in a readable format
func (i *IPInfo) Print() {
	fmt.Printf("  ISP:     %s\n", i.ISP)
	fmt.Printf("  City:    %s\n", i.City)
	fmt.Printf("  Country: %s\n", i.Country)
	fmt.Printf("  ASN:     %s\n", i.AS)
}
