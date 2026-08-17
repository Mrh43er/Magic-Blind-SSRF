# SSRF Exploitation Framework v3.0

A Go-based SSRF testing framework for authorized security assessments and lab environments.

> **Authorization required:** Use this project only against systems you own or have explicit permission to test. The framework includes active SSRF, internal-network, DNS-rebinding, and RCE-chain testing capabilities.

## Features

- Blind SSRF callback detection
- Cloud metadata testing
- Internal IPv4/IPv6 port scanning
- SSRF scheme testing
- DNS rebinding support
- RCE-chain testing
- Multi-threaded scanning
- Custom HTTP headers
- JSON and HTML reports
- Severity classification

## Requirements

- Go 1.21 or newer
- A permitted target or a local security lab

## Installation

Clone the repository and build the binary:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>.git
cd ssrf-framework
go mod tidy
go build -o ssrf-exploit .
```

You can also run it directly without creating a binary:

```bash
go run . -h
```

## Usage

The main options are:

| Flag | Description | Default |
|---|---|---|
| `-u` | Target URL | required |
| `-p` | Vulnerable parameter | `url` |
| `-X` | HTTP method | `GET` |
| `-H` | Custom headers, separated with `;` | empty |
| `-w` | Callback/webhook URL | empty |
| `-o` | JSON report path | `report.json` |
| `-html` | HTML report path | `report.html` |
| `-dns` | DNS server IP | `127.0.0.1` |
| `-t` | Number of workers | `30` |
| `-timeout` | Request timeout in seconds | `10` |
| `-mode` | Test mode | `all` |

### Modes

- `detect` — callback detection
- `metadata` — cloud metadata checks
- `scan` — internal port scanning
- `schemes` — SSRF scheme checks
- `rebinding` — DNS rebinding testing
- `rce` — RCE-chain testing
- `all` — run all supported checks

### Basic command format

```bash
./ssrf-exploit \
  -u "http://AUTHORIZED-TARGET.example/page?id=1" \
  -p url \
  -mode detect
```

### Authorized callback testing

```bash
./ssrf-exploit \
  -u "http://AUTHORIZED-TARGET.example/page?id=1" \
  -p url \
  -w "https://YOUR-AUTHORIZED-CALLBACK.example/endpoint" \
  -mode detect
```

### Generate reports

The framework writes JSON and HTML reports by default. Custom output paths can be selected with `-o` and `-html`:

```bash
./ssrf-exploit \
  -u "http://AUTHORIZED-TARGET.example/page?id=1" \
  -p url \
  -mode detect \
  -o results.json \
  -html results.html
```

## Custom Headers

Multiple headers can be passed as a semicolon-separated string:

```bash
./ssrf-exploit \
  -u "http://AUTHORIZED-TARGET.example/page?id=1" \
  -p url \
  -H "Authorization: Bearer <TOKEN>;X-Test: value" \
  -mode detect
```

## Recommended workflow

1. Use a local lab or a target explicitly in scope.
2. Start with `detect` to validate the SSRF behavior.
3. Use focused modes only when they are relevant to the authorized assessment.
4. Review `report.json` and `report.html` for evidence.
5. Keep concurrency and request rate appropriate for the target and the program's rules.

## Output

The framework can produce:

- `report.json` — machine-readable findings
- `report.html` — browser-friendly report

## Development

Format the Go source before committing:

```bash
gofmt -w main.go dnsrebind/*.go exploit/*.go report/*.go templates/*.go
```

Run the test/build checks:

```bash
go test ./...
go vet ./...
go build ./...
```

## Security / Responsible Use

Do not use this software to access, disrupt, or extract data from systems without authorization. For bug bounty programs, follow the program's scope, rate limits, testing restrictions, and disclosure rules.

## License

This repository is intended for authorized security testing and research. See `LICENSE` for the repository license terms.
