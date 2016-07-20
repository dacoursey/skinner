package main 

import "flag"
import "fmt"
// import "io/ioutil"
import "net/http"
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

    headersPresent := []header{}
    hostPtr := flag.String("t", "", "Target host.")
    redirPtr := flag.Bool("r", true, "Follow redirects.") // Not really used yet.
    flag.BoolVar(&verbose, "v", false, "Increase the number of status messages.")
    flag.Parse()

    if verbose {
        fmt.Printf("\nBeginning operations......\n")
    }

    // This is our map of all point-valued standard HTTP headers.
    var stdHeaders = map[string]int {
        "access-control-allow-origin": 2,
        "cache-control": 2,
        "content-security-policy": 10,
        "pragma": 2,
        "public-key-pins": 10,
        "strict-transport-security": 6,
        "tsv": 2,
        "x-content-type-options": 2,
        "x-frame-options": 4,
        "x-xss-protection": 2,
        "via": -2,
        "warning": -1, 
        "www-authenticate": -4,
        "x-content-security-policy": -5,
        "x-powered-by": -2,
        "x-ua-compatible": -2,
        "x-webkit-csp": -5,
    }

    if *hostPtr == "" {
        fmt.Println("No target host was specified.")
        return
    }

    // Here is where we start reaching out to the target.
    headersPresent, err := testTarget(*hostPtr, *redirPtr)

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

    // Let's print some pretty stuff.
    fmt.Printf("\n\n")
    fmt.Println("**************************************************")
    fmt.Println("*")
    fmt.Println("* Headers present")
    fmt.Println("*")
    fmt.Println("**************************************************")
    fmt.Printf("\n\n")

    for _, p := range headersPresent {
        fmt.Println(p)
    }

    // Let's print some more pretty stuff.
    fmt.Printf("\n\n")
    fmt.Println("**************************************************")
    fmt.Println("*")
    fmt.Println("**************************************************")
}


// This method is used to perform a basic HTTP request to the target host.
func testTarget(url string, redir bool) (h []header, err error) {

    client := &http.Client {
        Timeout: 10 * time.Second,
    }

    request, err := http.NewRequest("GET", url, nil)

    // Make the HTTP request to the target URL.
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
        //fmt.Println("Header:", k, "Value:", v)
        temp := header{k,v[0],0}
        //fmt.Println(temp)
        headers = append(headers, temp)
    }

    return headers, err
}