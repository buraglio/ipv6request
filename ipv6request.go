package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

// httpClient is used for making HTTP requests with a timeout.
var httpClient = &http.Client{Timeout: 8 * time.Second}

// bgpViewData represents the structure of the JSON response from BGPView API
// for ASN IPv6 prefixes.
type bgpViewData struct {
	Data struct {
		IPv6Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"ipv6_prefixes"`
	} `json:"data"`
}

// pageData holds the data to be rendered in the HTML template.
type pageData struct {
	ASN      string
	Prefixes []string
	Message  string // New field for the generated message
	Error    string
}

// indexTemplate is the HTML template for the web interface.
var indexTemplate = template.Must(template.New("index").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>IPv6 support</title>
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
        .message-box { background-color: #f9f9f9; border: 1px solid #eee; padding: 15px; border-radius: 5px; margin-top: 20px; white-space: pre-wrap; word-wrap: break-word; }
        ul { list-style-type: none; padding: 0; }
        li { margin-bottom: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>IPv6 Prefix Lookup</h1>
        <form method="POST" action="/">
            <label for="asn">Enter ASN (e.g., 19625):</label>
            <input type="text" id="asn" name="asn" value="{{.ASN}}" required>
            <input type="submit" value="Lookup IPv6 Prefixes">
        </form>

        {{if .Error}}
            <p class="error">Error: {{.Error}}</p>
        {{else if .ASN}}
            <h2>Results for ASN {{.ASN}}:</h2>
            {{if .Prefixes}}
                <ul>
                    {{range .Prefixes}}
                        <li>{{.}}</li>
                    {{end}}
                </ul>
            {{else}}
                <p class="info">No IPv6 prefixes registered for ASN {{.ASN}}.</p>
            {{end}}

            {{if .Message}}
                <h3>Generated IPv6 Request Message:</h3>
                <div class="message-box">{{.Message}}</div>
            {{end}}
        {{end}}
    </div>
</body>
</html>
`))

// lookupIPv6 queries the BGPView API for IPv6 prefixes associated with an ASN.
func lookupIPv6(asn string) ([]string, error) {
	bgpURL := fmt.Sprintf("https://api.bgpview.io/asn/%s/prefixes?type=ipv6", asn)
	resp, err := httpClient.Get(bgpURL)
	if err != nil {
		return nil, fmt.Errorf("BGPView API request failed: %w", err)
	}
	defer resp.Body.Close() // Ensure the response body is always closed

	if resp.StatusCode != http.StatusOK {
		// Return a specific error for non-200 status codes
		return nil, fmt.Errorf("BGPView API returned status %d for ASN %s", resp.StatusCode, asn)
	}

	var bgp bgpViewData // Use the defined struct
	if err := json.NewDecoder(resp.Body).Decode(&bgp); err != nil {
		// Return a specific error for JSON unmarshaling failures
		return nil, fmt.Errorf("failed to parse BGPView response for ASN %s: %w", asn, err)
	}

	var ipv6 []string
	// Iterate over the 'IPv6Prefixes' field
	for _, p := range bgp.Data.IPv6Prefixes {
		ipv6 = append(ipv6, p.Prefix)
	}

	// If no prefixes are found, return an empty slice and no error.
	// This allows the HTML template to display "No IPv6 prefixes registered"
	// instead of an error message.
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

	if r.Method == http.MethodPost {
		asn := r.FormValue("asn")
		data.ASN = asn

		ipv6Prefixes, err := lookupIPv6(asn)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Prefixes = ipv6Prefixes
			// Generate the message only if lookup was successful (even if no prefixes were found)
			data.Message = generateIPv6RequestMessage(asn, ipv6Prefixes)
		}
	}

	err := indexTemplate.Execute(w, data)
	if err != nil {
		http.Error(w, "Error rendering template: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

func main() {
	http.HandleFunc("/", formHandler)
	log.Println("Server starting on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
