package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// httpClient is used for making HTTP requests with a timeout.
var httpClient = &http.Client{Timeout: 8 * time.Second}

// Simple cache to reduce API calls
type Cache struct {
	data map[string]CacheEntry
	mu   sync.RWMutex
}

type CacheEntry struct {
	value     interface{}
	timestamp time.Time
	ttl       time.Duration
}

var cache = &Cache{
	data: make(map[string]CacheEntry),
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.data[key]
	if !exists {
		return nil, false
	}

	if time.Since(entry.timestamp) > entry.ttl {
		return nil, false
	}

	return entry.value, true
}

func (c *Cache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = CacheEntry{
		value:     value,
		timestamp: time.Now(),
		ttl:       ttl,
	}
}

// bgpViewData represents the structure of the JSON response from BGPView API
// for ASN IPv6 prefixes.
type bgpViewData struct {
	Data struct {
		IPv6Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"ipv6_prefixes"`
	} `json:"data"`
}

// bgpViewIPData represents the structure of the JSON response from BGPView API
// for IP-to-ASN lookup.
type bgpViewIPData struct {
	Data struct {
		IP       string `json:"ip"`
		Prefixes []struct {
			ASN struct {
				ASN         int    `json:"asn"`
				Name        string `json:"name"`
				Description string `json:"description"`
				CountryCode string `json:"country_code"`
			} `json:"asn"`
		} `json:"prefixes"`
	} `json:"data"`
}

// bgpViewASNData represents the structure of the JSON response from BGPView API
// for detailed ASN information lookup.
type bgpViewASNData struct {
	Data struct {
		ASN              int      `json:"asn"`
		Name             string   `json:"name"`
		DescriptionShort string   `json:"description_short"`
		DescriptionFull  []string `json:"description_full"`
		CountryCode      string   `json:"country_code"`
		Website          string   `json:"website"`
		EmailContacts    []string `json:"email_contacts"`
		AbuseContacts    []string `json:"abuse_contacts"`
		TrafficRatio     string   `json:"traffic_ratio"`
		OwnerAddress     []string `json:"owner_address"`
		RIRAllocation    struct {
			RIRName          string `json:"rir_name"`
			CountryCode      string `json:"country_code"`
			DateAllocated    string `json:"date_allocated"`
			AllocationStatus string `json:"allocation_status"`
		} `json:"rir_allocation"`
		IANAAssignment struct {
			AssignmentStatus string `json:"assignment_status"`
			Description      string `json:"description"`
			WhoisServer      string `json:"whois_server"`
			DateAssigned     string `json:"date_assigned"`
		} `json:"iana_assignment"`
		DateUpdated string `json:"date_updated"`
	} `json:"data"`
}

// ASNDetails holds detailed information about an ASN
type ASNDetails struct {
	ASN              string
	Name             string
	DescriptionShort string
	DescriptionFull  []string
	CountryCode      string
	Website          string
	EmailContacts    []string
	AbuseContacts    []string
	TrafficRatio     string
	OwnerAddress     []string
	RIRAllocation    string
	IANAAssignment   string
	WhoisServer      string
	DateUpdated      string
}

// pageData holds the data to be rendered in the HTML template.
type pageData struct {
	ASN          string
	Prefixes     []string
	Error        string
	SourceIP     string
	DetectedASN  string
	ASNName      string
	AutoDetected bool
	ASNDetails   *ASNDetails
}

// indexTemplate is the HTML template for the web interface.
var indexTemplate = template.Must(template.New("index").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>Does your provider Support IPv6?</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        .container { max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ccc; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #333; }
        form { display: flex; flex-direction: column; gap: 10px; margin-bottom: 20px; }
        label { font-weight: bold; }
        input[type="text"] { padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        input[type="submit"] { padding: 10px 15px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        input[type="submit"]:hover { background-color: #0056b3; }
        .error { color: red; font-weight: bold; margin-top: 10px; }
        .info { color: #555; margin-top: 10px; }
        .message-box { background-color: #f9f9f9; border: 1px solid #eee; padding: 15px; border-radius: 5px; margin-top: 20px; white-space: pre-wrap; word-wrap: break-word; line-height: 1.6; }
        .auto-detected { background-color: #e7f3ff; border: 1px solid #b3d9ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .auto-detected h3 { margin-top: 0; color: #0056b3; }
        .ip-info { display: flex; justify-content: space-between; margin-bottom: 10px; }
        .ip-info strong { color: #333; }
        .asn-details { background-color: #f8f9fa; border: 1px solid #dee2e6; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .asn-details h3 { margin-top: 0; color: #495057; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .detail-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin: 15px 0; }
        .detail-item { background: white; padding: 12px; border-radius: 4px; border-left: 4px solid #007bff; }
        .detail-label { font-weight: bold; color: #495057; font-size: 0.9em; margin-bottom: 5px; }
        .detail-value { color: #212529; }
        .contact-list { margin: 5px 0; }
        .contact-list li { background: #e9ecef; padding: 4px 8px; margin: 2px 0; border-radius: 3px; font-size: 0.9em; }
        .address-line { margin: 2px 0; }
        .collapsible { background-color: #007bff; color: white; cursor: pointer; padding: 12px; width: 100%; border: none; text-align: left; outline: none; font-size: 16px; border-radius: 5px; margin: 10px 0; }
        .collapsible:hover { background-color: #0056b3; }
        .collapsible:after { content: '\002B'; color: white; font-weight: bold; float: right; margin-left: 5px; }
        .collapsible.active:after { content: "\2212"; }
        .collapsible-content { max-height: 0; overflow: hidden; transition: max-height 0.2s ease-out; background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 0 0 5px 5px; }
        .collapsible-content.active { max-height: none; }
        .btn-generate { background-color: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 14px; margin: 10px 5px 10px 0; }
        .btn-generate:hover { background-color: #218838; }
        .btn-secondary { background-color: #6c757d; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 14px; margin: 10px 5px 10px 0; }
        .btn-secondary:hover { background-color: #5a6268; }
        ul { list-style-type: none; padding: 0; }
        li { margin-bottom: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Does your provider support IPv6?</h1>

        {{if .AutoDetected}}
        <div class="auto-detected">
            <h3>🎯 Auto-detected Information</h3>
            <div class="ip-info">
                <span><strong>Your IP:</strong> {{.SourceIP}}</span>
                <span><strong>ASN:</strong> {{.DetectedASN}} ({{.ASNName}})</span>
            </div>
            <p class="info">We've automatically detected your ISP's ASN based on your IP address. You can use this or enter a different ASN below.</p>
        </div>
        {{else if .SourceIP}}
        <div class="auto-detected">
            <h3>ℹ️ Your Connection</h3>
            <p><strong>Your IP:</strong> {{.SourceIP}}</p>
            <p class="info">Unable to automatically detect ASN for your IP. Please enter an ASN manually below.</p>
        </div>
        {{end}}

        <form method="POST" action="/">
            <label for="asn">Enter ASN (e.g., 19625){{if .AutoDetected}} or use auto-detected{{end}}:</label>
            <input type="text" id="asn" name="asn" value="{{.ASN}}" required>
            <input type="submit" value="Lookup IPv6 Prefixes">
        </form>

        {{if .Error}}
            <p class="error">Error: {{.Error}}</p>
        {{else if .ASN}}
            <h2>Results for ASN {{.ASN}}:</h2>

            {{if .ASNDetails}}
            <button class="collapsible" onclick="toggleCollapsible(this)">📋 View Detailed AS Organization Information</button>
            <div class="collapsible-content">
                <div class="asn-details" style="margin: 0; border: none; background: transparent;">
                    <h3 style="border-bottom: none;">AS Organization Details</h3>
                <div class="detail-grid">
                    <div class="detail-item">
                        <div class="detail-label">ASN</div>
                        <div class="detail-value">{{.ASNDetails.ASN}}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Organization Name</div>
                        <div class="detail-value">{{.ASNDetails.Name}}</div>
                    </div>
                    {{if .ASNDetails.DescriptionShort}}
                    <div class="detail-item">
                        <div class="detail-label">Description</div>
                        <div class="detail-value">{{.ASNDetails.DescriptionShort}}</div>
                    </div>
                    {{end}}
                    {{if .ASNDetails.CountryCode}}
                    <div class="detail-item">
                        <div class="detail-label">Country</div>
                        <div class="detail-value">{{.ASNDetails.CountryCode}}</div>
                    </div>
                    {{end}}
                    {{if .ASNDetails.Website}}
                    <div class="detail-item">
                        <div class="detail-label">Website</div>
                        <div class="detail-value"><a href="{{.ASNDetails.Website}}" target="_blank">{{.ASNDetails.Website}}</a></div>
                    </div>
                    {{end}}
                    {{if .ASNDetails.TrafficRatio}}
                    <div class="detail-item">
                        <div class="detail-label">Traffic Ratio</div>
                        <div class="detail-value">{{.ASNDetails.TrafficRatio}}</div>
                    </div>
                    {{end}}
                    {{if .ASNDetails.RIRAllocation}}
                    <div class="detail-item">
                        <div class="detail-label">Regional Internet Registry</div>
                        <div class="detail-value">{{.ASNDetails.RIRAllocation}}</div>
                    </div>
                    {{end}}
                    {{if .ASNDetails.IANAAssignment}}
                    <div class="detail-item">
                        <div class="detail-label">IANA Assignment</div>
                        <div class="detail-value">{{.ASNDetails.IANAAssignment}}</div>
                    </div>
                    {{end}}
                    {{if .ASNDetails.WhoisServer}}
                    <div class="detail-item">
                        <div class="detail-label">WHOIS Server</div>
                        <div class="detail-value">{{.ASNDetails.WhoisServer}}</div>
                    </div>
                    {{end}}
                </div>

                {{if .ASNDetails.OwnerAddress}}
                <div class="detail-item">
                    <div class="detail-label">Address</div>
                    <div class="detail-value">
                        {{range .ASNDetails.OwnerAddress}}
                            <div class="address-line">{{.}}</div>
                        {{end}}
                    </div>
                </div>
                {{end}}

                {{if .ASNDetails.EmailContacts}}
                <div class="detail-item">
                    <div class="detail-label">Email Contacts</div>
                    <div class="detail-value">
                        <ul class="contact-list">
                            {{range .ASNDetails.EmailContacts}}
                                <li><a href="mailto:{{.}}">{{.}}</a></li>
                            {{end}}
                        </ul>
                    </div>
                </div>
                {{end}}

                {{if .ASNDetails.AbuseContacts}}
                <div class="detail-item">
                    <div class="detail-label">Abuse Contacts</div>
                    <div class="detail-value">
                        <ul class="contact-list">
                            {{range .ASNDetails.AbuseContacts}}
                                <li><a href="mailto:{{.}}">{{.}}</a></li>
                            {{end}}
                        </ul>
                    </div>
                </div>
                {{end}}

                {{if .ASNDetails.DateUpdated}}
                <div class="detail-item">
                    <div class="detail-label">Last Updated</div>
                    <div class="detail-value">{{.ASNDetails.DateUpdated}}</div>
                </div>
                {{end}}
                </div>
            </div>
            {{end}}

            {{if .Prefixes}}
                <h3>📡 IPv6 Prefixes</h3>
                <ul>
                    {{range .Prefixes}}
                        <li>{{.}}</li>
                    {{end}}
                </ul>
            {{else}}
                <p class="info">No IPv6 prefixes registered for ASN {{.ASN}}.</p>
            {{end}}

            <div style="margin: 20px 0;">
                <button class="btn-generate" onclick="generateMessage('{{.ASN}}')">✉️ Generate IPv6 Request Message</button>
                <button class="btn-secondary" onclick="copyToClipboard()">📋 Copy Message</button>
            </div>

            <div id="message-container" style="display: none;">
                <h3>✉️ Generated IPv6 Request Message</h3>
                <div class="message-box" id="generated-message"></div>
            </div>
        {{end}}
    </div>

    <script>
        // Toggle collapsible sections
        function toggleCollapsible(element) {
            element.classList.toggle("active");
            var content = element.nextElementSibling;
            content.classList.toggle("active");

            if (content.classList.contains("active")) {
                content.style.maxHeight = content.scrollHeight + "px";
            } else {
                content.style.maxHeight = "0";
            }
        }

        // Generate IPv6 request message
        function generateMessage(asn) {
            // Get the IPv6 prefixes from the page
            var prefixes = [];

            // Find the IPv6 Prefixes section and get the list items
            var h3Elements = document.querySelectorAll('h3');
            for (var i = 0; i < h3Elements.length; i++) {
                if (h3Elements[i].textContent.includes('IPv6 Prefixes')) {
                    var nextElement = h3Elements[i].nextElementSibling;
                    if (nextElement && nextElement.tagName === 'UL') {
                        var liElements = nextElement.querySelectorAll('li');
                        for (var j = 0; j < liElements.length; j++) {
                            prefixes.push(liElements[j].textContent.trim());
                        }
                    }
                    break;
                }
            }

            var organizationSection;
            var requestSection;

            if (prefixes.length > 0) {
                var blocksOrLinks = prefixes.join(', ');
                organizationSection = 'I see that you have ' + blocksOrLinks + ' registered to your organization.';
                requestSection = 'Because IPv4 is a legacy protocol with severely limited resources available and IPv6 is the current Internet protocol as defined by the IETF, I respectfully request IPv6 support for my current service offering. This would ensure compatibility with the modern Internet infrastructure and provide better connectivity for your customers.';
            } else {
                organizationSection = 'You currently have no IPv6 associated with your ASN. This represents a significant opportunity to modernize your network infrastructure.';
                requestSection = 'As IPv4 address space becomes increasingly scarce and expensive, implementing IPv6 is essential for future growth and compatibility. I respectfully request that you prioritize IPv6 deployment for your network and customer services.\n\nTo get started with IPv6, you can request address space from your Regional Internet Registry:\n- ARIN: https://www.arin.net/resources/guide/ipv6/first_request/\n- RIPE NCC: https://www.ripe.net/manage-ips-and-asns/ipv6/request-ipv6/\n- APNIC: https://www.apnic.net/community/ipv6/get-ipv6/\n- AFRINIC: https://afrinic.net/support/resource-members/how-can-i-request-for-an-ipv6-prefix?lang=en\n- LACNIC: https://www.lacnic.net/1016/2/lacnic/get-ip-addresses_asns';
            }

            var message = 'I am a current customer of your internet service. IPv6 now results in nearly 50% of the global internet traffic (see current adoption trends: https://stats.ipv6.army/?page=Historical%20Trends), over 80% of mobile traffic, and is available on all major content providers.\n\n📊 GROWTH EVIDENCE:\nThe growth trend is clear - IPv6 adoption has been steadily increasing over the past 5 years as shown in the Global IPv6 Adoption Timeline. You can view the historical trends and adoption graphs here:\nhttps://stats.ipv6.army/?page=Historical%20Trends\n\nMajor content providers and ISPs worldwide have implemented IPv6 to future-proof their networks and meet growing demand.\n\n🌐 YOUR ORGANIZATION:\n' + organizationSection + '\n\n📋 REQUEST:\n' + requestSection;

            document.getElementById('generated-message').textContent = message;
            document.getElementById('message-container').style.display = 'block';

            // Scroll to the message
            document.getElementById('message-container').scrollIntoView({ behavior: 'smooth' });
        }

        // Copy message to clipboard
        function copyToClipboard() {
            var messageElement = document.getElementById('generated-message');
            if (messageElement && messageElement.textContent) {
                navigator.clipboard.writeText(messageElement.textContent).then(function() {
                    // Temporarily change button text to show success
                    var copyBtn = event.target;
                    var originalText = copyBtn.textContent;
                    copyBtn.textContent = '✅ Copied!';
                    copyBtn.style.backgroundColor = '#28a745';

                    setTimeout(function() {
                        copyBtn.textContent = originalText;
                        copyBtn.style.backgroundColor = '#6c757d';
                    }, 2000);
                }).catch(function(err) {
                    alert('Failed to copy message to clipboard');
                });
            } else {
                alert('Please generate a message first');
            }
        }
    </script>
</body>
</html>
`))

// getClientIP extracts the real client IP address from the HTTP request,
// handling cases where the server is behind a proxy or load balancer.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (most common proxy header)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, get the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header (another common proxy header)
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// lookupASNDetails queries the BGPView API for detailed ASN information.
func lookupASNDetails(asn string) (*ASNDetails, error) {
	cacheKey := "asn_details_" + asn

	// Check cache first
	if cached, found := cache.Get(cacheKey); found {
		return cached.(*ASNDetails), nil
	}

	bgpURL := fmt.Sprintf("https://api.bgpview.io/asn/%s", asn)

	resp, err := retryWithBackoff(func() (*http.Response, error) {
		return httpClient.Get(bgpURL)
	}, 3)

	if err != nil {
		return nil, fmt.Errorf("BGPView ASN details API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == 429 {
			return nil, fmt.Errorf("BGPView API rate limit exceeded for ASN %s details", asn)
		}
		return nil, fmt.Errorf("BGPView ASN details API returned status %d for ASN %s", resp.StatusCode, asn)
	}

	var bgpASN bgpViewASNData
	if err := json.NewDecoder(resp.Body).Decode(&bgpASN); err != nil {
		return nil, fmt.Errorf("failed to parse BGPView ASN details response for %s: %w", asn, err)
	}

	details := &ASNDetails{
		ASN:              fmt.Sprintf("%d", bgpASN.Data.ASN),
		Name:             bgpASN.Data.Name,
		DescriptionShort: bgpASN.Data.DescriptionShort,
		DescriptionFull:  bgpASN.Data.DescriptionFull,
		CountryCode:      bgpASN.Data.CountryCode,
		Website:          bgpASN.Data.Website,
		EmailContacts:    bgpASN.Data.EmailContacts,
		AbuseContacts:    bgpASN.Data.AbuseContacts,
		TrafficRatio:     bgpASN.Data.TrafficRatio,
		OwnerAddress:     bgpASN.Data.OwnerAddress,
		WhoisServer:      bgpASN.Data.IANAAssignment.WhoisServer,
		DateUpdated:      bgpASN.Data.DateUpdated,
	}

	if bgpASN.Data.RIRAllocation.RIRName != "" {
		details.RIRAllocation = bgpASN.Data.RIRAllocation.RIRName
	}
	if bgpASN.Data.IANAAssignment.Description != "" {
		details.IANAAssignment = bgpASN.Data.IANAAssignment.Description
	}

	// Cache the result for 2 hours (ASN details change less frequently)
	cache.Set(cacheKey, details, 2*time.Hour)

	return details, nil
}

// retryWithBackoff executes a function with exponential backoff retry logic
func retryWithBackoff(fn func() (*http.Response, error), maxRetries int) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err = fn()

		if err != nil {
			if attempt == maxRetries-1 {
				return nil, err
			}

			// Wait with exponential backoff
			waitTime := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			log.Printf("API request failed (attempt %d/%d), retrying in %v: %v", attempt+1, maxRetries, waitTime, err)
			time.Sleep(waitTime)
			continue
		}

		// If we get a 429 (rate limit), wait longer
		if resp.StatusCode == 429 {
			if attempt == maxRetries-1 {
				return resp, nil // Return the 429 response on final attempt
			}

			resp.Body.Close()
			waitTime := time.Duration(math.Pow(2, float64(attempt+2))) * time.Second // Longer wait for rate limits
			log.Printf("Rate limited (429), retrying in %v (attempt %d/%d)", waitTime, attempt+1, maxRetries)
			time.Sleep(waitTime)
			continue
		}

		// Success or non-retryable error
		return resp, nil
	}

	return resp, err
}

// lookupASNByIP queries the BGPView API to find the ASN associated with an IP address.
func lookupASNByIP(ip string) (string, string, error) {
	cacheKey := "ip_" + ip

	// Check cache first
	if cached, found := cache.Get(cacheKey); found {
		result := cached.([]string)
		return result[0], result[1], nil
	}

	bgpURL := fmt.Sprintf("https://api.bgpview.io/ip/%s", ip)

	resp, err := retryWithBackoff(func() (*http.Response, error) {
		return httpClient.Get(bgpURL)
	}, 3)

	if err != nil {
		return "", "", fmt.Errorf("BGPView IP API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == 429 {
			return "", "", fmt.Errorf("BGPView API rate limit exceeded for IP %s. Please try again in a few minutes", ip)
		}
		return "", "", fmt.Errorf("BGPView IP API returned status %d for IP %s", resp.StatusCode, ip)
	}

	var bgpIP bgpViewIPData
	if err := json.NewDecoder(resp.Body).Decode(&bgpIP); err != nil {
		return "", "", fmt.Errorf("failed to parse BGPView IP response for %s: %w", ip, err)
	}

	// Get the most specific prefix (first one) which typically has the most accurate ASN
	if len(bgpIP.Data.Prefixes) > 0 {
		asn := fmt.Sprintf("%d", bgpIP.Data.Prefixes[0].ASN.ASN)
		name := bgpIP.Data.Prefixes[0].ASN.Name
		if name == "" {
			name = bgpIP.Data.Prefixes[0].ASN.Description
		}

		// Cache the result for 30 minutes
		cache.Set(cacheKey, []string{asn, name}, 30*time.Minute)

		return asn, name, nil
	}

	return "", "", fmt.Errorf("no ASN found for IP %s", ip)
}

// lookupIPv6 queries the BGPView API for IPv6 prefixes associated with an ASN.
func lookupIPv6(asn string) ([]string, error) {
	cacheKey := "asn_" + asn

	// Check cache first
	if cached, found := cache.Get(cacheKey); found {
		return cached.([]string), nil
	}

	bgpURL := fmt.Sprintf("https://api.bgpview.io/asn/%s/prefixes?type=ipv6", asn)

	resp, err := retryWithBackoff(func() (*http.Response, error) {
		return httpClient.Get(bgpURL)
	}, 3)

	if err != nil {
		return nil, fmt.Errorf("BGPView API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == 429 {
			return nil, fmt.Errorf("BGPView API rate limit exceeded for ASN %s. Please try again in a few minutes", asn)
		}
		return nil, fmt.Errorf("BGPView API returned status %d for ASN %s", resp.StatusCode, asn)
	}

	var bgp bgpViewData
	if err := json.NewDecoder(resp.Body).Decode(&bgp); err != nil {
		return nil, fmt.Errorf("failed to parse BGPView response for ASN %s: %w", asn, err)
	}

	var ipv6 []string
	for _, p := range bgp.Data.IPv6Prefixes {
		ipv6 = append(ipv6, p.Prefix)
	}

	// Cache the result for 1 hour (IPv6 prefixes change less frequently)
	cache.Set(cacheKey, ipv6, 1*time.Hour)

	return ipv6, nil
}

// generateIPv6RequestMessage constructs a message based on the returned IPv6 blocks.
func generateIPv6RequestMessage(asn string, ipv6Blocks []string) string {
	var blocksOrLinks string
	if len(ipv6Blocks) > 0 {
		blocksOrLinks = strings.Join(ipv6Blocks, ", ")
	} else {
		blocksOrLinks = `
- ARIN: [https://www.arin.net/resources/guide/ipv6/first_request/](https://www.arin.net/resources/guide/ipv6/first_request/)
- RIPE NCC: [https://www.ripe.net/manage-ips-and-asns/ipv6/request-ipv6/](https://www.ripe.net/manage-ips-and-asns/ipv6/request-ipv6/)
- APNIC: [https://www.apnic.net/community/ipv6/get-ipv6/](https://www.apnic.net/community/ipv6/get-ipv6/)
- AFRINIC: [https://afrinic.net/support/resource-members/how-can-i-request-for-an-ipv6-prefix?lang=en](https://afrinic.net/support/resource-members/how-can-i-request-for-an-ipv6-prefix?lang=en)
- LACNIC: [https://www.lacnic.net/1016/2/lacnic/get-ip-addresses_asns](https://www.lacnic.net/1016/2/lacnic/get-ip-addresses_asns)
`
	}

	message := fmt.Sprintf(`I am a current customer of your internet service. IPv6 now results in nearly 50%% of the global internet traffic (see https://stats.ipv6.army), over 80%% of mobile traffic, and is available on all major content providers. I see that you have %s registered to your organization. Because IPv4 is a legacy protocol with severely limited resources available and IPv6 is the current Internet protocol as defined by the IETF, I respectfully request IPv6 support for my current service offering.`, blocksOrLinks)

	return message
}

// formHandler handles HTTP requests for the web interface.
func formHandler(w http.ResponseWriter, r *http.Request) {
	data := pageData{}

	// Always try to detect the client's IP and ASN
	clientIP := getClientIP(r)
	data.SourceIP = clientIP

	// Attempt to auto-detect ASN from client IP
	if clientIP != "" {
		detectedASN, asnName, err := lookupASNByIP(clientIP)
		if err == nil {
			data.DetectedASN = detectedASN
			data.ASNName = asnName
			data.AutoDetected = true
		}
	}

	if r.Method == http.MethodPost {
		asn := r.FormValue("asn")
		data.ASN = asn

		// Fetch detailed ASN information
		asnDetails, detailsErr := lookupASNDetails(asn)
		if detailsErr == nil {
			data.ASNDetails = asnDetails
		}

		ipv6Prefixes, err := lookupIPv6(asn)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Prefixes = ipv6Prefixes
		}
	} else if data.AutoDetected {
		// For GET requests, if we auto-detected an ASN, pre-populate the form
		data.ASN = data.DetectedASN
	}

	err := indexTemplate.Execute(w, data)
	if err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func main() {
	// Check if this is the daemon child process before parsing flags
	for _, arg := range os.Args[1:] {
		if arg == "--daemon-child" {
			runDaemonServer()
			return
		}
	}

	// Parse command-line flags
	daemon := flag.Bool("d", false, "Run as daemon (background process on IPv6 localhost)")
	port := flag.String("port", "8080", "Port to listen on")
	flag.Parse()

	// If daemon flag is set, fork and run in background
	if *daemon {
		runAsDaemon()
		return
	}

	// Set up signal handling for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Normal mode - bind to all interfaces
	bindAddr := ":" + *port

	// Start HTTP server in a goroutine
	server := &http.Server{
		Addr:    bindAddr,
		Handler: nil,
	}

	http.HandleFunc("/", formHandler)

	go func() {
		log.Printf("Server starting on port %s...", *port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for signal
	<-c
	log.Println("Received interrupt signal, shutting down gracefully...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}
	log.Println("Server stopped")
}

// runAsDaemon forks the process and runs it in the background on IPv6 localhost
func runAsDaemon() {
	// Create a new process group to detach from parent
	if os.Getppid() != 1 {
		// Re-execute the program without the -d flag, but pass a special flag to indicate daemon child
		args := []string{}
		for _, arg := range os.Args[1:] {
			if arg != "-d" {
				args = append(args, arg)
			}
		}
		args = append(args, "--daemon-child")

		cmd := exec.Command(os.Args[0], args...)
		cmd.Start()
		log.Printf("Started daemon process with PID: %d (IPv6 localhost only)", cmd.Process.Pid)
		os.Exit(0)
	}

	// This is the daemon process - run the main server logic with IPv6 binding
	runDaemonServer()
}

// runDaemonServer runs the HTTP server bound to IPv6 localhost
func runDaemonServer() {
	log.Println("Running as daemon on IPv6 localhost...")

	// Extract port from command line args, default to 8080
	port := "8080"
	for i, arg := range os.Args[1:] {
		if arg == "-port" && i+1 < len(os.Args[1:]) {
			port = os.Args[i+2]
			break
		}
	}

	// Set up signal handling for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Bind only to IPv6 localhost
	bindAddr := "[::1]:" + port

	// Start HTTP server in a goroutine
	server := &http.Server{
		Addr:    bindAddr,
		Handler: nil,
	}

	http.HandleFunc("/", formHandler)

	go func() {
		log.Printf("Daemon server starting on IPv6 localhost port %s...", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for signal
	<-c
	log.Println("Received interrupt signal, shutting down gracefully...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}
	log.Println("Server stopped")

	// Redirect stdout and stderr to log file (optional)
	// You can uncomment this if you want to log to a file
	/*
		logFile, err := os.OpenFile("ipv6request.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			os.Stdout = logFile
			os.Stderr = logFile
			log.SetOutput(logFile)
		}
	*/
}
