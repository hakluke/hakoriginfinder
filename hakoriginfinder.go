package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
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

// sha256Hash returns the hex-encoded SHA256 hash of a string
func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Regex patterns for normalizeBody (compiled once for performance)
var (
	reNonceQuoted = regexp.MustCompile(`nonce="[^"]*"`)
	reNonceUnquoted = regexp.MustCompile(`nonce=[a-zA-Z0-9+/=]+`)
	reCsrf = regexp.MustCompile(`(?i)csrf[_-]?token["\s:=]+["']?[a-zA-Z0-9+/=_-]+["']?`)
	reTimestamp = regexp.MustCompile(`\b\d{10,13}\b`)
	reUuid = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	reHexToken = regexp.MustCompile(`[a-f0-9]{32,64}`)
)

// normalizeBody strips dynamic tokens (nonces, CSRF tokens, timestamps, UUIDs,
// session IDs) from response bodies so that pages with per-request dynamic
// content can be accurately compared.
func normalizeBody(body string) string {
	body = reNonceQuoted.ReplaceAllString(body, `nonce=""`)
	body = reNonceUnquoted.ReplaceAllString(body, "nonce=")
	body = reCsrf.ReplaceAllString(body, "csrf_token=")
	body = reTimestamp.ReplaceAllString(body, "TIMESTAMP")
	body = reUuid.ReplaceAllString(body, "UUID")
	body = reHexToken.ReplaceAllString(body, "HEXTOKEN")
	return body
}

// certMatchesHostname checks if a TLS certificate covers the given hostname,
// including wildcard matching (e.g., *.example.com matches sub.example.com).
func certMatchesHostname(cert *x509.Certificate, hostname string) bool {
	// Check SANs
	for _, san := range cert.DNSNames {
		if san == hostname {
			return true
		}
		if strings.HasPrefix(san, "*.") {
			wildcard := san[2:]
			if strings.HasSuffix(hostname, wildcard) && hostname != wildcard {
				return true
			}
		}
	}
	// Check CN
	cn := cert.Subject.CommonName
	if cn == hostname {
		return true
	}
	if strings.HasPrefix(cn, "*.") {
		wildcard := cn[2:]
		if strings.HasSuffix(hostname, wildcard) && hostname != wildcard {
			return true
		}
	}
	return false
}

// checkTLSCert connects to ip:port with the given SNI hostname and returns
// whether the certificate matches and the list of SANs found.
func checkTLSCert(ip string, port string, hostname string, timeout time.Duration) (bool, []string) {
	addr := ip + ":" + port
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         hostname,
	})
	if err != nil {
		return false, nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return false, nil
	}

	cert := certs[0]
	var sans []string
	sans = append(sans, cert.DNSNames...)
	if cert.Subject.CommonName != "" {
		sans = append(sans, cert.Subject.CommonName)
	}

	return certMatchesHostname(cert, hostname), sans
}

// baseline holds the pre-fetched response data for the target
type baseline struct {
	body           string
	normalizedBody string
	hash           string
	statusCode     int
	contentLength  int
}

// Make HTTP request, check response
func worker(ips <-chan string, resChan chan<- string, wg *sync.WaitGroup, client *http.Client, u *url.URL, bl *baseline, threshold int, ports []string, smartMode bool, certOnly bool, timeout time.Duration) {
	defer wg.Done()
	for ip := range ips {
		schemes := []string{"http", "https"}
		for _, scheme := range schemes {
			for _, port := range ports {

				// Check if ip address from stdin is ipv6
				ipAddr := ip
				if strings.Count(ip, ":") >= 2 {
					ipAddr = "[" + ip + "]"
				}

				// TLS cert check (smart mode, HTTPS only)
				if smartMode && scheme == "https" {
					certMatch, sans := checkTLSCert(ip, port, u.Hostname(), timeout)
					if certMatch {
						sanStr := strings.Join(sans, ",")
						if len(sanStr) > 100 {
							sanStr = sanStr[:100] + "..."
						}
						resChan <- fmt.Sprintf("CERT_MATCH %s://%s:%s%s cert_sans=%s", scheme, ipAddr, port, u.Path, sanStr)
						if certOnly {
							continue
						}
					}
				}

				if certOnly {
					continue
				}

				// Create ip URL
				ipUrl := scheme + "://" + ipAddr + ":" + port + u.Path

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
				resp.Body.Close()
				if err != nil {
					fmt.Println("Error: ", err)
					continue
				}
				text := string(body)

				if smartMode {
					// --- Smart matching pipeline ---

					// 1. SHA256 hash exact match (instant, no string comparison needed)
					hash := sha256Hash(text)
					if hash == bl.hash {
						resChan <- fmt.Sprintf("HASH_MATCH %s 0", ipUrl)
						continue
					}

					// 2. Status code + content length pre-filter
					//    If both are wildly different, skip the expensive Levenshtein
					statusMatch := resp.StatusCode == bl.statusCode
					lengthRatio := 0.0
					if bl.contentLength > 0 {
						smaller := len(text)
						larger := bl.contentLength
						if smaller > larger {
							smaller, larger = larger, smaller
						}
						lengthRatio = float64(smaller) / float64(larger)
					} else if len(text) == 0 {
						lengthRatio = 1.0
					}

					if !statusMatch && lengthRatio < 0.5 {
						resChan <- fmt.Sprintf("NOMATCH %s status=%d/%d len_ratio=%.2f", ipUrl, resp.StatusCode, bl.statusCode, lengthRatio)
						continue
					}

					// 3. Normalized Levenshtein (strips nonces, CSRFs, timestamps first)
					normalizedText := normalizeBody(text)
					lev := levenshtein([]rune(normalizedText), []rune(bl.normalizedBody))

					if lev <= threshold {
						resChan <- fmt.Sprintf("MATCH %s %d", ipUrl, lev)
					} else {
						resChan <- fmt.Sprintf("NOMATCH %s %d", ipUrl, lev)
					}
				} else {
					// --- Original behavior (backwards compatible) ---
					lev := levenshtein([]rune(text), []rune(bl.body))

					if lev <= threshold {
						resChan <- "MATCH " + ipUrl + " " + strconv.Itoa(lev)
					} else {
						resChan <- "NOMATCH " + ipUrl + " " + strconv.Itoa(lev)
					}
				}
			}
		}
	}
}

func main() {

	// Set up CLI flags
	workers := flag.Int("t", 32, "number of threads")
	threshold := flag.Int("l", 5, "levenshtein threshold, higher means more lenient")
	hostname := flag.String("h", "", "scheme://host[:port]/url of site, e.g. https://www.hakluke.com:443/blog")
	scanPorts := flag.String("p", "80,443", "comma separated ports to scan for IP addresses given via stdin, e.g. 80,443,8000,8080,8443")
	smartMode := flag.Bool("smart", false, "enable smart matching: TLS cert check, SHA256 hash pre-filter, body normalization")
	certOnly := flag.Bool("cert-only", false, "only check TLS certificates, skip HTTP requests (fastest, implies -smart)")
	flag.Parse()

	if *certOnly {
		*smartMode = true
	}

	// Sanity check, print usage if no hostname specified
	u, urlerror := url.Parse(*hostname)
	if urlerror != nil || *hostname == "" {
		fmt.Println("A list of IP addresses must be provided via stdin, along with an host/URL of the website you are trying to find the origin of.")
		fmt.Println("\nE.g. prips 1.1.1.0/24 | hakoriginfinder -h https://www.hakluke.com")
		fmt.Println("\nSmart mode (recommended — adds TLS cert check, hash pre-filter, body normalization):")
		fmt.Println("  prips 1.1.1.0/24 | hakoriginfinder -h https://www.hakluke.com -smart")
		fmt.Println("\nCert-only mode (fastest — only checks if TLS cert matches, no HTTP):")
		fmt.Println("  prips 1.1.1.0/24 | hakoriginfinder -h https://www.hakluke.com -cert-only")
		fmt.Println("\nOptions:")
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

	timeout := 5 * time.Second

	// Set up Transport (disable SSL verification)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Set up HTTP client
	var RedirectAttemptedError = errors.New("redirect")
	var client = &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return RedirectAttemptedError
		},
	}

	// Build baseline
	bl := &baseline{}

	if !*certOnly {
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
		resp.Body.Close()
		if err != nil {
			log.Fatal("Error reading HTTP response from original host.", err)
		}

		bl.body = string(body)
		bl.statusCode = resp.StatusCode
		bl.contentLength = len(body)

		if *smartMode {
			bl.hash = sha256Hash(bl.body)
			bl.normalizedBody = normalizeBody(bl.body)
			fmt.Fprintf(os.Stderr, "[smart] Baseline: %d status, %d bytes, hash %s...\n", bl.statusCode, bl.contentLength, bl.hash[:12])
		}
	} else {
		fmt.Fprintln(os.Stderr, "[cert-only] Skipping HTTP baseline — only checking TLS certificates")
	}

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
		go worker(ips, resChan, &wg, client, u, bl, *threshold, ports, *smartMode, *certOnly, timeout)
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
