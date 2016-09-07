package main

import "flag"
import "fmt"
import "io/ioutil"
import "net/http"
import "net/url"
import "strings"
import "time"
import "github.com/dacoursey/skinner/header"
import "github.com/dacoursey/skinner/print/text"

// Global Vars
var verbose = false

func main() {

	// First we grab all of the command flags.
	hostPtr := flag.String("t", "http://www.qualys.com", "Target host.") // For now we only accept full URL's
	filePtr := flag.String("f", "", "File with list of targets - one URL per line.")
	redirPtr := flag.Bool("r", true, "Follow redirects.") // Not really used yet.
	rawPtr := flag.Bool("a", false, "Print all raw headers.")
	flag.BoolVar(&verbose, "v", false, "Increase the number of status messages.")
	flag.Parse()

	// Variables used for some reason or another.
	headersPresent := []header.Header{}
	headersUnknown := []header.Header{}
	headersNotPresent := []string{}
	hostList := []string{}
	isHTTPS := false
	totalScore := 60

	if verbose {
		fmt.Printf("\nBeginning operations......\n")
	}

	if *hostPtr == "" && *filePtr == "" {
		fmt.Println("No target host was specified.")
		flag.PrintDefaults()
		return
	} else if *hostPtr != "" && *filePtr != "" {
		fmt.Println("Please specify only one target host source.")
		flag.PrintDefaults()
		return
	} else if *hostPtr == "" && *filePtr != "" {
		// Need some error handling on this but it's being weird.
		hostList = loadHostsFile(*filePtr)

	} else {
		hostList = append(hostList, *filePtr)
	}

	// Cycle through our list of hosts and start scanning.
	for i := range hostList {

		if verbose {
			fmt.Printf("\nValidating target: %v \n", i)
		}

		// Make sure the target string is usable.
		target, err := validateTarget(hostList[i])

		if target.Scheme == "https" {
			isHTTPS = true
		}

		// Here is where we start reaching out to the target.
		headersPresent, err = scanTarget(hostList[i], *redirPtr)

		if err != nil {
			fmt.Println("We have encountered an error, exiting...")
			return
		}

		headersPresent, err = checkHeaders(headersPresent)

		// We need to double check a few things depending on HTTP/HTTPS
		if isHTTPS {
			for i := range headersPresent {
				if strings.ToLower(headersPresent[i].Name) == "strict-transport-security" {
					val := strings.ToLower(headersPresent[i].Value)
					if strings.Contains(val, "max-age") && strings.Contains(val, "includesubdomains") {
						headersPresent[i].Points = 6
					} else if strings.Contains(val, "max-age") && !strings.Contains(val, "includesubdomains") {
						headersPresent[i].Points = 5
					} else if strings.Contains(val, "includesubdomains") && !strings.Contains(val, "max-age") {
						headersPresent[i].Points = 1
					} else {
						headersPresent[i].Points = -4
					}
				} else {
					headersNotPresent = append(headersNotPresent, "strict-transport-security")
				}
			}
		}

		// Make a slice of headers we find that are not expected.
		// These could lead to information disclosure.
		for p := range headersPresent {
			if headersPresent[p].Points != 0 {
				totalScore += headersPresent[p].Points
			} else {
				headersUnknown = append(headersUnknown, headersPresent[p])
			}
		}

		// Let's print some results.
		if *rawPtr {
			text.PrintAll(totalScore, headersPresent, headersUnknown)
		} else {
			text.PrintScore(totalScore)
		}
	}

}

func loadHostsFile(path string) (hosts []string) {
	content, err := ioutil.ReadFile(path)

	if err != nil {
		fmt.Printf("Error attempting to open file: %v", err.Error())
	}

	hosts = strings.Split(string(content), "\n")
	return hosts
}

// We need to make sure the target string is a valid URL before we attempt
// any operations on some jacked up mess.
func validateTarget(target string) (u *url.URL, err error) {

	cleanTarget, err := url.Parse(target)
	if err != nil {
		fmt.Println(err)
		return
	}

	if cleanTarget.Scheme == "" || cleanTarget.Host == "" {
		fmt.Println("Not a valid URL...  exiting.")
		return
	}

	return cleanTarget, err
}

// This method is used to perform a basic HTTP request to the target host.
func scanTarget(url string, redir bool) (h []header.Header, err error) {

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Make the HTTP request to the target URL.
	request, err := http.NewRequest("GET", url, nil)
	response, err := client.Do(request)

	if err != nil {
		fmt.Printf("Error message: %v \n", err)
	}

	if verbose {
		fmt.Printf("Target %v responded.\n", url)
	}

	if response.StatusCode != http.StatusOK {
		fmt.Printf("Server return non-200 status: %v\n", response.Status)
	}

	headers := []header.Header{}

	// Print out all headers.
	for k, v := range response.Header {
		temp := header.Header{Name: k, Value: v[0], Points: 0}
		headers = append(headers, temp)
	}

	return headers, err
}

func checkHeaders(headersPresent []header.Header) (h []header.Header, err error) {
	headersInfoLeak := header.GetInfoLeak()

	// This is our source of all point-Valued standard HTTP headers.
	// We compare the headers retrieved from the target to the standard
	// header list to start scoring.
	// 46 good points.
	// -21 bad points.
	for i := range headersPresent {
		n := strings.ToLower(headersPresent[i].Name)
		switch n {
		case "access-control-allow-origin":
			if headersPresent[i].Value != "*" {
				headersPresent[i].Points = 2
			}
		case "cache-control":
			// This needs to be improved to account for variations
			headersPresent[i].Points = 2
		case "content-security-policy":
			// This needs to be improved to account for variations
			headersPresent[i].Points = 10
		case "pragma":
			if strings.ToLower(headersPresent[i].Value) == "no-cache" {
				headersPresent[i].Points = 2
			}
		case "public-key-pins":
			val := strings.ToLower(headersPresent[i].Value)
			sha := strings.Contains(val, "pin-sha256")
			age := strings.Contains(val, "max-age")
			sub := strings.Contains(val, "includesubdomains")
			rep := strings.Contains(val, "report-uri")

			if sha && age && sub && rep {
				headersPresent[i].Points = 8
			} else if sha && age && sub && !rep {
				headersPresent[i].Points = 7
			} else if sha && age && !sub && !rep {
				headersPresent[i].Points = 6
			} else {
				headersPresent[i].Points = 0
			}
		case "tsv":
			headersPresent[i].Points = 2
		case "x-content-type-options":
			if strings.ToLower(headersPresent[i].Value) == "nosniff" {
				headersPresent[i].Points = 2
			}
		case "x-frame-options":
			val := strings.ToLower(headersPresent[i].Value)
			if val == "deny" {
				headersPresent[i].Points = 4
			} else if val == "sameorigin" || strings.Contains(val, "allow-from") {
				headersPresent[i].Points = 2
			}
		case "x-xss-protection":
			if strings.ToLower(headersPresent[i].Value) == "1; mode=block" {
				headersPresent[i].Points = 2
			}
		case "set-cookie":
			val := strings.ToLower(headersPresent[i].Value)
			if strings.Contains(val, "httponly") && strings.Contains(val, "secure") {
				headersPresent[i].Points = 6
			} else if strings.Contains(val, "httponly") && !strings.Contains(val, "secure") {
				headersPresent[i].Points = 3
			} else if strings.Contains(val, "secure") && !strings.Contains(val, "httponly") {
				headersPresent[i].Points = 3
			} else {
				headersPresent[i].Points = -4
			}
		case "via":
			headersPresent[i].Points = -2
		case "warning":
			headersPresent[i].Points = -1
		case "www-authenticate":
			headersPresent[i].Points = -4
		case "x-content-security-policy":
			headersPresent[i].Points = -3
		case "x-powered-by":
			headersPresent[i].Points = -2
		case "x-ua-compatible":
			headersPresent[i].Points = -2
		case "x-webkit-csp":
			headersPresent[i].Points = -3
		default:
			for l := range headersInfoLeak {
				if n == strings.ToLower(headersInfoLeak[l]) {
					headersPresent[i].Points = -1
				}
			}
		}
	}

	return headersPresent, err
}

// Not implemented yet.
func checkLeakage(h string) bool {
	// Assume false and hope for the best...
	present := false

	return present
}
