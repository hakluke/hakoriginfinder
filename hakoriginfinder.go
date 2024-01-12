package main

import (
        "bufio"
        "crypto/tls"
        "errors"
        "flag"
        "fmt"
        "io/ioutil"
        "log"
        "net/http"
        "net/url"
        "os"
        "strconv"
        "strings"
        "sync"
        "time"
)

// Levenshtein distance calculator, from https://www.golangprograms.com/golang-program-for-implementation-of-levenshtein-distance.html
func levenshtein(str1, str2 []rune) int {
        s1len := len(str1)
        s2len := len(str2)
        column := make([]int, len(str1)+1)

        for y := 1; y <= s1len; y++ {
                column[y] = y
        }
        for x := 1; x <= s2len; x++ {
                column[0] = x
                lastkey := x - 1
                for y := 1; y <= s1len; y++ {
                        oldkey := column[y]
                        var incr int
                        if str1[y-1] != str2[x-1] {
                                incr = 1
                        }

                        column[y] = minimum(column[y]+1, column[y-1]+1, lastkey+incr)
                        lastkey = oldkey
                }
        }
        return column[s1len]
}

// required for levenshtein function
func minimum(a, b, c int) int {
        if a < b {
                if a < c {
                        return a
                }
        } else {
                if b < c {
                        return b
                }
        }
        return c
}

// Make HTTP request, check response
func worker(ips <-chan string, resChan chan<- string, wg *sync.WaitGroup, client *http.Client, u *url.URL, ogBody string, threshold int, ports []string) {
        defer wg.Done()
        for ip := range ips {
                // http and https schemes
                schemes := []string{"http", "https"}
                for _, scheme := range schemes {
                        for _, port := range ports {

                                // Check if ip address from stdin is ipv6
                                if strings.Count(ip, ":") >= 2 {
                                        ip = "[" + ip + "]"
                                }

                                // Create ip URL
                                ipUrl := scheme + "://" + ip + ":" + port + u.Path
                                
                                // Create a request
                                req, err := http.NewRequest("GET", ipUrl, nil)
                                if err != nil {
                                        fmt.Println("Error sending HTTP request", err)
                                        continue
                                }

                                // Add the custom host header to the request (can be host:port)
                                req.Host = u.Host

                                // Do the request
                                resp, err := client.Do(req)
                                if err != nil {
                                        // Redirects are skipped here silently as errors
                                        // due to CheckRedirect
                                        continue
                                }

                                body, err := ioutil.ReadAll(resp.Body)
                                if err != nil {
                                        fmt.Println("Error: ", err)
                                        continue
                                }
                                text := string(body)

                                lev := levenshtein([]rune(text), []rune(ogBody))

                                if lev <= threshold {
                                        resChan <- "MATCH " + ipUrl + " " + strconv.Itoa(lev)
                                } else {
                                        resChan <- "NOMATCH " + ipUrl + " " + strconv.Itoa(lev)

                                }
                        }
                }
        }
}

func main() {

        // Set up CLI flags
        workers := flag.Int("t", 32, "numbers of threads")
        threshold := flag.Int("l", 5, "levenshtein threshold, higher means more lenient")
        hostname := flag.String("h", "", "scheme://host[:port]/url of site, e.g. https://www.hakluke.com:443/blog")
        scanPorts := flag.String("p", "80,443", "comma separated ports to scan for IP addresses given via stdin, e.g. 80,443,8000,8080,8443")
        flag.Parse()

        // Sanity check, print usage if no hostname specified
        u, urlerror := url.Parse(*hostname)
        if urlerror != nil || *hostname == "" {
                fmt.Println("A list of IP addresses must be provided via stdin, along with an host/URL of the website you are trying to find the origin of.\n\nE.g. prips 1.1.1.0/24 | hakoriginfinder -h https://www.hakluke.com\n\nOptions:")
                flag.PrintDefaults()
                os.Exit(2)
	    }

        // Handle ports argument
        ports := strings.Split(*scanPorts, ",")

        // IP addresses are provided via stdin
        scanner := bufio.NewScanner(os.Stdin)

        // this channel will contain the ip addresses from stdin
        ips := make(chan string)

        // this is the channel used to push a response to
        resChan := make(chan string)

        // this channel indicates when the jobs are done
        done := make(chan struct{})

        // Set up Transport (disable SSL verification)
        transport := &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        }

        // Set up HTTP client
        var RedirectAttemptedError = errors.New("redirect")
        var client = &http.Client{
                Timeout:   time.Second * 5,
                Transport: transport,
                CheckRedirect: func(req *http.Request, via []*http.Request) error {
                        return RedirectAttemptedError
                },
        }

        // Get original URL
        resp := &http.Response{}
        var err error
        resp, err = client.Get(u.Scheme + "://" + u.Host + u.Path)
        // Handle redirect error
        for errors.Is(err, RedirectAttemptedError) {
                redirectUrl, _ := resp.Location()
                fmt.Println("Redirect", resp.StatusCode, "to:", redirectUrl)
                u = redirectUrl
                resp, err = client.Get(u.Scheme + "://" + u.Host + u.Path)
        }
        // Handle any error
        if err != nil {
                log.Println("Error getting original URL:", err)
                os.Exit(2)
        }

        // Read the response
        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                log.Fatal("Error reading HTTP response from original host.", err)
        }

        // Convert body to string
        ogBody := string(body)

        // Set up waitgroup
        var wg sync.WaitGroup
        wg.Add(*workers)

        // Wait for workers to be done, then close the "done" channel
        go func() {
                wg.Wait()
                close(done)
        }()

        // Fire up workers
        for i := 0; i < *workers; i++ {
                go worker(ips, resChan, &wg, client, u, ogBody, *threshold, ports)
        }

        // Add ips from stdin to ips channel
        go func() {
                for scanner.Scan() {
                        ips <- scanner.Text()
                }
                if err := scanner.Err(); err != nil {
                        log.Println(err)
                }
                close(ips)
        }()

        // print responses from response channel, or finish
        for {
                select {
                case <-done:
                        return
                case res := <-resChan:
                        // print results
                        fmt.Println(res)
                }
        }
}
