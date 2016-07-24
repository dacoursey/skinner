package main 

import "flag"
import "fmt"
import "net/http"
import "net/url"
import "strings"
import "time"

// Global Vars
var verbose = false

type header struct {
	name string
	value string
	points int
}

func (h *header) SetPoints(points int) {
    h.points = points
}

func main(){

    // First we grab all of the command flags.
    hostPtr := flag.String("t", "https://qualys.com", "Target host.") // For now we only accept full URL's
    redirPtr := flag.Bool("r", true, "Follow redirects.") // Not really used yet.
    rawPtr := flag.Bool("a", false, "Print all raw headers.")
    flag.BoolVar(&verbose, "v", false, "Increase the number of status messages.")
    flag.Parse()

    // Variables used for some reason.
    headersPresent := []header{}
    headersNotPresent := []string{}
    isHTTPS := false
    totalScore := 60

    // This is our map of all point-valued standard HTTP headers.
    // 40 good points.
    // -17 bad points.
    var stdHeaders = map[string]int {
        "access-control-allow-origin": 2,
        "cache-control": 2,
        "content-security-policy": 10,
        "pragma": 2,
        "public-key-pins": 8,
        "strict-transport-security": 6,
        "tsv": 2,
        "x-content-type-options": 2,
        "x-frame-options": 4,
        "x-xss-protection": 2,
        "via": -2,
        "warning": -1, 
        "www-authenticate": -4,
        "x-content-security-policy": -3,
        "x-powered-by": -2,
        "x-ua-compatible": -2,
        "x-webkit-csp": -3,
    }

    if verbose { fmt.Printf("\nBeginning operations......\n") }

    if *hostPtr == "" {
        fmt.Println("No target host was specified.")
        return
    }

    if verbose { fmt.Printf("\nValidating target......\n") }

    // Make sure the target string is usable.
    target, err := validateTarget(*hostPtr)

    if target.Scheme == "https" {
        isHTTPS = true
    }

    // Here is where we start reaching out to the target.
    headersPresent, err = testTarget(*hostPtr, *redirPtr)

    if err != nil {
        fmt.Println("We have encountered an error, exiting...")
        return
    }

    // We compare the headers retrieved from the target to the standard
    // header list to start scoring.
    for i := range headersPresent {
        for k, v := range stdHeaders{
            if strings.ToLower(headersPresent[i].name) == k {
                headersPresent[i].points = v
            }
        }
    }

    // We need to double check a few things depending on HTTP/HTTPS
    if isHTTPS {
        for i := range headersPresent {
            if  strings.ToLower(headersPresent[i].name) == "strict-transport-security" {
                headersPresent[i].points = 6
            } else {
                //x := len(headersNotPresent) + 1
                //headersNotPresent[x] = "strict-transport-security"
                headersNotPresent = append(headersNotPresent, "strict-transport-security")
            }
        }
    }

    for i := range headersPresent {
        totalScore += headersPresent[i].points
    }
    
    // Let's print some pretty stuff.
    fmt.Printf("\n\n")
    fmt.Println("**************************************************")
    fmt.Println("* Scoring")
    fmt.Println("**************************************************")
    fmt.Printf("\n")

    fmt.Printf("Total Score: %v\n", totalScore)

    // Print the raw list of headers.
    if *rawPtr {

        fmt.Printf("\n")
        fmt.Println("**************************************************")
        fmt.Println("* Headers present")
        fmt.Println("**************************************************")
        fmt.Printf("\n")

        for _, p := range headersPresent {
            fmt.Println(p)
        }
    }

    // Let's print some more pretty stuff.
    fmt.Printf("\n")
    fmt.Println("**************************************************")
    fmt.Println("**************************************************")
}

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
func testTarget(url string, redir bool) (h []header, err error) {

    client := &http.Client {
        Timeout: 10 * time.Second,
    }

    // Make the HTTP request to the target URL.
    request, err := http.NewRequest("GET", url, nil)
    response, err := client.Do(request)

    if err != nil {
        fmt.Printf("Error message: %v \n", err)
    }

    if verbose { fmt.Printf("Target %v responded.\n", url)}
    
    if response.StatusCode != http.StatusOK {
                fmt.Printf("Server return non-200 status: %v\n", response.Status)
        }
    
    headers := []header{}

    // Print out all headers.
    for k, v := range response.Header {
        temp := header{k,v[0],0}
        headers = append(headers, temp)
    }

    return headers, err
}