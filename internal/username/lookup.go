// Package username checks if a username exists on multiple platforms
package username

import (
	"fmt"
	"net/http" // for HTTP requests
	"sync"     // for WaitGroup (running goroutines in parallel)
	"time"     // for setting request timeouts
)

// PlatformResult holds the result for one platform check
type PlatformResult struct {
	Platform string // e.g. "GitHub"
	URL      string // full profile URL
	Found    bool   // true if profile exists
	Error    string // error message if request failed
}

// platforms is a map of platform name -> URL template
// %s will be replaced with the actual username
var platforms = map[string]string{
	"GitHub":    "https://github.com/%s",
	"Twitter":   "https://twitter.com/%s",
	"Instagram": "https://www.instagram.com/%s/",
	"Facebook":  "https://www.facebook.com/%s",
	"LinkedIn":  "https://www.linkedin.com/in/%s",
	"Reddit":    "https://www.reddit.com/user/%s",
}

// Lookup checks all platforms in parallel using goroutines
func Lookup(username string) []PlatformResult {
	results := make([]PlatformResult, 0, len(platforms))

	var mu sync.Mutex     // mutex prevents race condition when writing to results slice
	var wg sync.WaitGroup // WaitGroup waits for all goroutines to finish

	// custom HTTP client settings
	client := &http.Client{
		Timeout: 8 * time.Second, // don't wait more than 8 seconds per request
		// some sites redirect to homepage instead of returning 404
		// we stop at the first redirect to detect this behavior
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// launch one goroutine per platform (all run at the same time)
	for platform, urlTemplate := range platforms {
		wg.Add(1) // tell WaitGroup we're starting one more goroutine

		// use go keyword to run this function concurrently
		go func(p, tmpl string) {
			defer wg.Done() // mark this goroutine as done when function exits

			url := fmt.Sprintf(tmpl, username)
			result := PlatformResult{Platform: p, URL: url}

			// build the request with a browser-like User-Agent header
			// some sites block requests without this header
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				result.Error = err.Error()
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")

			// send the request
			resp, err := client.Do(req)
			if err != nil {
				result.Error = err.Error()
			} else {
				defer resp.Body.Close()
				// HTTP 200 = page found, anything else = not found
				result.Found = resp.StatusCode == 200
			}

			// lock before writing to shared slice to avoid race conditions
			mu.Lock()
			results = append(results, result)
			mu.Unlock()

		}(platform, urlTemplate) // pass loop variables into goroutine to avoid closure issues
	}

	wg.Wait() // block here until all goroutines are done
	return results
}

// PrintResults displays each platform result in the terminal
func PrintResults(results []PlatformResult) {
	for _, r := range results {
		status := "Not Found"
		if r.Found {
			status = "Found"
		}
		if r.Error != "" {
			status = "Error: " + r.Error
		}
		// %-12s = left-aligned string with 12 character width (for alignment)
		fmt.Printf("  %-12s %s\n", r.Platform+":", status)
	}
}
