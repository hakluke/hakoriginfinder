# hakoriginfinder

Tool for discovering the origin host behind a reverse proxy. Useful for bypassing WAFs and other reverse proxies.

## How does it work?

This tool will first make a HTTP request to the hostname/URL that you provide and store the response, then it will make a request to every IP address that you provide via HTTP (80) or HTTPS (443) depending on URL, with the `Host` header set to the original host(:port). Each response is then compared to the original using the Levenshtein algorithm to determine similarity. If the response is similar, it will be deemed a match.

## Usage

Provide the list of IP addresses via stdin, and the original hostname via the -h option. For example:

```
prips 93.184.216.0/24 | hakoriginfinder -h https://example.com:443/foo
```

You may set the Levenshtein distance threshold with `-l`. The lower the number, the more similar the matches need to be for it to be considered a match, the default is 5.

The number of threads may be set with `-t`, default is 32.

The hostname is set with `-h`, there is no default.

## Output

The output is 3 columns, separated by spaces. The first column is either "MATCH" or "NOMATCH" depending on whether the Levenshtein threshold was reached or not. The second column is the URL being tested, and the third column is the Levenshtein score.

### Output example

```
hakluke$ prips 1.1.1.0/24 | hakoriginfinder -l 500 -h https://one.one.one.one/index.html
NOMATCH http://1.1.1.0/index.html 56506
NOMATCH http://1.1.1.9/index.html 56506
NOMATCH http://1.1.1.30/index.html 56506
NOMATCH http://1.1.1.20/index.html 56506
NOMATCH http://1.1.1.16/index.html 56506
NOMATCH http://1.1.1.24/index.html 56506
NOMATCH http://1.1.1.10/index.html 56506
NOMATCH http://1.1.1.17/index.html 56506
NOMATCH http://1.1.1.4/index.html 56506
... snipped for brevity ...
NOMATCH http://1.1.1.254/index.html 56506
NOMATCH http://1.1.1.253/index.html 56506
MATCH http://1.1.1.1/index.html 228
NOMATCH http://1.1.1.2/index.html 19487
NOMATCH http://1.1.1.3/index.html 19487
```

## Installation

Install golang, then run:

```
go install github.com/hakluke/hakoriginfinder@latest
```
