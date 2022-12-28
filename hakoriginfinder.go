package main

import (
        "bufio"
        "crypto/tls"
        "flag"
        "fmt"
        "io/ioutil"
        "log"
        "net"
        "net/http"
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
func worker(ips <-chan string, resChan chan<- string, wg *sync.WaitGroup, client *http.Client, hostname string, ogBody string, threshold int) {
        defer wg.Done()
        var urls []string
        for ip := range ips {

                // make a http and https url if no protocol given. If given, just use that
                if !strings.HasPrefix(ip, "http://") && !strings.HasPrefix(ip, "https://") {
                        urls = []string{"http://" + ip, "https://" + ip}
                } else {
                        urls = []string{ip}
                }

                for _, url := range urls {
                        // Create a request
                        req, err := http.NewRequest("GET", url, nil)
                        if err != nil {
                                fmt.Println("Error sending HTTP request", err)
                                continue
                        }

                        // Add the custom host header to the request
                        req.Header.Add("Host", hostname)

                        // Do the request
                        resp, err := client.Do(req)
                        if err != nil {
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
                                resChan <- "MATCH " + url + " " + strconv.Itoa(lev)
                        } else {
                                fmt.Fprintf(os.Stderr, "NOMATCH %s %s\n", url, strconv.Itoa(lev));
                        }

                }
        }
}

var timeout = time.Duration(2 * time.Second)

func dialTimeout(network, addr string) (net.Conn, error) {
    return net.DialTimeout(network, addr, timeout)
}

func main() {

        // Set up CLI flags
        workers := flag.Int("t", 32, "numbers of threads")
        threshold := flag.Int("l", 5, "levenshtein threshold, higher means more lenient")
        timeout := flag.Int("T", 5, "Timeout in seconds")
        hostname := flag.String("h", "", "hostname of site, e.g. www.hakluke.com")
        hostnameSSL := flag.Bool("s", false, "Original hostname is over SSL (default: false)")
        hostnamePort := flag.String("p", "", "Original hostname listen port")
        flag.Parse()

        // Sanity check, print usage if no hostname specified
        if *hostname == "" {
                fmt.Println("A list of IP addresses must be provided via stdin, along with a hostname of the website you are trying to find the origin of.\n\nE.g. prips 1.1.1.0/24 | hakoriginfinder -h www.hakluke.com\n\nOptions:")
                flag.PrintDefaults()
                os.Exit(2)
        }

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
                Dial: dialTimeout,
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        }

        // Set up HTTP client
        var client = &http.Client{
                Timeout:   time.Second * time.Duration(*timeout),
                Transport: transport,
        }

        // Set up waitgroup
        var wg sync.WaitGroup
        wg.Add(*workers)

        // Wait for workers to be done, then close the "done" channel
        go func() {
                wg.Wait()
                close(done)
        }()

        // Get original URL
        resp := &http.Response{}
        var err error
        if *hostnameSSL {
                port:="443"
                if *hostnamePort != "" {
                        port=*hostnamePort
                } else {

                }
                resp, err = client.Get("https://" + *hostname + ":"+port)
                if err != nil {
                        log.Println("Error getting original URL:", err)
                        os.Exit(2)
                }
        } else {
                port:="80"
                if *hostnamePort != "" {
                        port=*hostnamePort
                }
                resp, err = client.Get("http://" + *hostname + ":"+port)
                if err != nil {
                        log.Println("Error getting original URL:", err)
                        os.Exit(2)
                }
        }


        // Read the response
        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                log.Fatal("Error reading HTTP response from original host.", err)
        }

        // Convert body to string
        ogBody := string(body)

        // Fire up workers
        for i := 0; i < *workers; i++ {
                go worker(ips, resChan, &wg, client, *hostname, ogBody, *threshold)
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
