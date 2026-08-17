# Magic-Blind-SSRF

A Go-based SSRF security testing framework designed for authorized security assessments, penetration testing, bug bounty research, and controlled security labs.

The framework provides a structured workflow for SSRF detection and validation, including callback-based detection, cloud metadata checks, internal network testing, DNS rebinding support, and automated reporting.

> **Disclaimer:** This project is intended for authorized security testing only. Do not use it against systems or networks without explicit permission.

## Features

* SSRF detection and validation
* Out-of-band / callback-based detection
* Cloud metadata testing
* Internal network testing
* DNS rebinding support
* Multiple SSRF testing modes
* Automated JSON reporting
* HTML report generation
* Concurrent security testing
* Configurable request parameters
* Written in Go

## Requirements

* Go 1.22 or newer
* Linux, macOS, or Windows

Check your Go installation:

```bash
go version
```

## Installation

Clone the repository:

```bash
git clone https://github.com/Mrh43er/Magic-Blind-SSRF.git
cd Magic-Blind-SSRF
```

Download dependencies:

```bash
go mod tidy
```

Build the framework:

```bash
go build -o magic-blind-ssrf .
```

Run:

```bash
./magic-blind-ssrf -h
```

On Windows:

```powershell
go build -o magic-blind-ssrf.exe .
.\magic-blind-ssrf.exe -h
```

## Usage

Always test only targets that you are authorized to assess.

Display available options:

```bash
./magic-blind-ssrf -h
```

Basic authorized test:

```bash
./magic-blind-ssrf -u "https://authorized-target.example" -p url
```

Use the available modes and options shown by:

```bash
./magic-blind-ssrf -h
```

The exact parameters may vary depending on the selected testing mode.

## Output

The framework can generate structured results for further analysis.

JSON output:

```bash
./magic-blind-ssrf ... -o results.json
```

HTML report:

```bash
./magic-blind-ssrf ... -html results.html
```

Generated reports can be used for manual verification and vulnerability documentation.

## Workflow

A typical authorized assessment can follow this workflow:

```text
Target
  │
  ▼
Input / Parameter Identification
  │
  ▼
SSRF Detection
  │
  ├── Callback Validation
  ├── Metadata Checks
  ├── Internal Network Testing
  └── DNS Rebinding
  │
  ▼
Result Analysis
  │
  ▼
JSON / HTML Report
```

## Project Structure

```text
Magic-Blind-SSRF/
├── main.go
├── go.mod
├── go.sum
├── exploit/
├── dnsrebind/
├── report/
├── scanner/
└── README.md
```

The exact project structure may evolve as the framework is developed.

## Security Research

Magic-Blind-SSRF can be useful for:

* Authorized penetration testing
* Bug bounty research
* SSRF validation
* Security laboratories
* Internal security assessments
* Security research and education

## Responsible Disclosure

If you discover a vulnerability in a system while using this framework, follow the target organization's responsible disclosure policy and report the issue through the appropriate security channel.

## Contributing

Contributions, bug reports, improvements, and security research are welcome.

Before submitting a pull request:

```bash
gofmt -w .
go test ./...
go vet ./...
```

Please keep contributions focused and include appropriate documentation for new functionality.

## License

This project is provided for security research and authorized testing purposes.

See `LICENSE` for the applicable license terms.

## Disclaimer

The authors are not responsible for misuse of this software.

You are responsible for ensuring that you have explicit authorization before testing any target, network, service, or infrastructure.
