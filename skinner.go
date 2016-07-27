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

// func (h *header) SetPoints(points int) {
//     h.points = points
// }

func main(){

    // First we grab all of the command flags.
    hostPtr := flag.String("t", "", "Target host.") // For now we only accept full URL's
    //filePtr := flag.String("f", "", "File with list of targets - one URL per line.")
    redirPtr := flag.Bool("r", true, "Follow redirects.") // Not really used yet.
    rawPtr := flag.Bool("a", false, "Print all raw headers.")
    flag.BoolVar(&verbose, "v", false, "Increase the number of status messages.")
    flag.Parse()

    // Variables used for some reason.
    headersPresent := []header{}
    headersUnknown := []header{}
    headersNotPresent := []string{}
    isHTTPS := false
    totalScore := 60

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

    // This is our source of all point-valued standard HTTP headers.
    // We compare the headers retrieved from the target to the standard
    // header list to start scoring.
    // 46 good points.
    // -21 bad points.
    for i :=  range headersPresent {
        n := strings.ToLower(headersPresent[i].name)
        switch {
        case n == "access-control-allow-origin":
            if headersPresent[i].value != "*" {
                headersPresent[i].points = 2
            }
        case n == "cache-control":
            // This needs to be improved to account for variations
            headersPresent[i].points = 2
        case n == "content-security-policy":
            // This needs to be improved to account for variations
            headersPresent[i].points = 10
        case n == "pragma":
            if strings.ToLower(headersPresent[i].value) == "no-cache" {
                headersPresent[i].points = 2
            }
        case n == "public-key-pins":
            val := strings.ToLower(headersPresent[i].value)
            sha := strings.Contains(val, "pin-sha256")
            age := strings.Contains(val, "max-age")
            sub := strings.Contains(val, "includesubdomains")
            rep := strings.Contains(val, "report-uri")

            if sha && age && sub && rep {
                headersPresent[i].points = 8
            } else if sha && age && sub && !rep {
                headersPresent[i].points = 7
            } else if sha && age && !sub && !rep {
                headersPresent[i].points = 6
            } else {
                headersPresent[i].points = 0
            }
        case n == "tsv":
            headersPresent[i].points = 2
        case n == "x-content-type-options":
            if strings.ToLower(headersPresent[i].value) == "nosniff" {
                headersPresent[i].points = 2
            }
        case n == "x-frame-options":
            val := strings.ToLower(headersPresent[i].value)
            if val == "deny" {
                headersPresent[i].points = 4
            } else if val == "sameorigin" || strings.Contains(val, "allow-from") {
                headersPresent[i].points = 2
            }
        case n == "x-xss-protection":
            if strings.ToLower(headersPresent[i].value) == "1; mode=block" {
                headersPresent[i].points = 2
            }
        case n == "set-cookie":
            val := strings.ToLower(headersPresent[i].value)
            if strings.Contains(val, "httponly") && strings.Contains(val, "secure") {
                headersPresent[i].points = 6
            } else if strings.Contains(val, "httponly") && !strings.Contains(val, "secure") {
                headersPresent[i].points = 3
            } else if strings.Contains(val, "secure") && !strings.Contains(val, "httponly") {
                headersPresent[i].points = 3
            } else {
                headersPresent[i].points = -4
            }
        case n == "via":
            headersPresent[i].points = -2
        case n == "warning":
            headersPresent[i].points = -1
        case n == "www-authenticate":
            headersPresent[i].points = -4
        case n == "x-content-security-policy":
            headersPresent[i].points = -3
        case n == "x-powered-by":
            headersPresent[i].points = -2
        case n == "x-ua-compatible":
            headersPresent[i].points = -2
        case n == "x-webkit-csp":
            headersPresent[i].points = -3
        }
    }

    // We need to double check a few things depending on HTTP/HTTPS
    if isHTTPS {
        for i := range headersPresent {
            if  strings.ToLower(headersPresent[i].name) == "strict-transport-security" {
                val := strings.ToLower(headersPresent[i].value)
                if strings.Contains(val, "max-age") && strings.Contains(val, "includesubdomains") {
                    headersPresent[i].points = 6
                } else if strings.Contains(val, "max-age") && !strings.Contains(val, "includesubdomains") {
                    headersPresent[i].points = 5
                } else if strings.Contains(val, "includesubdomains") && !strings.Contains(val, "max-age") {
                    headersPresent[i].points = 1
                } else {
                    headersPresent[i].points = -4
                }
            } else {
                headersNotPresent = append(headersNotPresent, "strict-transport-security")
            }
        }
    }

    for p := range headersPresent {
        if headersPresent[p].points != 0 {
            totalScore += headersPresent[p].points
        } else {
            headersUnknown = append(headersUnknown, headersPresent[p])
        }
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
        fmt.Println("* Scored Headers")
        fmt.Println("**************************************************")
        fmt.Printf("\n")

        // ToDo: Come back and clean this up with column alignment.
        for i := range headersPresent {
            if headersPresent[i].points != 0 {
                h := headersPresent[i].name
                v := headersPresent[i].value
                p := headersPresent[i].points
                fmt.Printf("Header: %v \t\t Value: %v \t\t Score: %v\n", h, v, p)
            }
        }

        fmt.Printf("\n")
        fmt.Println("**************************************************")
        fmt.Println("* Unknown Headers")
        fmt.Println("* Evaluate the following headers for information leakage.")
        fmt.Println("**************************************************")
        fmt.Printf("\n")

        for i := range headersUnknown {
            h := headersUnknown[i].name
            v := headersUnknown[i].value
            fmt.Printf("Header: %v \t\t Value: %v\n", h, v)
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